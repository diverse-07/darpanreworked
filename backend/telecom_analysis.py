"""Evidence-linked PS03 telecom analytics for any normalized case."""
from __future__ import annotations

import io
import math
import re
import textwrap
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, time, timedelta, timezone

IST = timezone(timedelta(hours=5, minutes=30))
RESULT_LIMIT = 250


@dataclass
class Finding:
    title: str
    summary: str
    rows: list[dict] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)


def stamp(value):
    return value.astimezone(IST).isoformat(sep=" ", timespec="milliseconds")


def source(row):
    return f'{row["source_file"]} {row["source_locator"]} · SHA-256 {row["source_sha"][:12]}'


def subjects(case):
    rows = case.query("""
        SELECT caller_msisdn AS number FROM cdr_calls
        UNION SELECT callee_msisdn FROM cdr_calls
        UNION SELECT caller_msisdn FROM ipdr_cgnat WHERE caller_msisdn IS NOT NULL
        UNION SELECT phone FROM suspect_master ORDER BY number
    """)
    return [row["number"] for row in rows]


def names(case):
    result = defaultdict(list)
    for entry in case.all("suspect_master"):
        result[entry["name"].strip().casefold()].append(entry["phone"])
    return result


def calls_for(case, number, start=None, end=None):
    clauses = ["(caller_msisdn=? OR callee_msisdn=?)"]
    params = [number, number]
    if start is not None:
        clauses.append("timestamp>=?")
        params.append(start)
    if end is not None:
        clauses.append("timestamp<?")
        params.append(end)
    rows = case.query("SELECT * FROM cdr_calls WHERE " + " AND ".join(clauses)
                      + " ORDER BY timestamp, source_sha, source_locator", params)
    for row in rows:
        outgoing = row["caller_msisdn"] == number
        row["direction"] = "Outgoing" if outgoing else "Incoming"
        row["peer"] = row["callee_msisdn"] if outgoing else row["caller_msisdn"]
    return rows


def call_evidence(rows):
    return [{"Time (IST)": stamp(r["timestamp"]), "Caller": r["caller_msisdn"], "Callee": r["callee_msisdn"],
             "Direction": r["direction"], "Seconds": r["duration_sec"], "Tower": r["cell_tower_id"],
             "IMEI": r["imei"], "IMSI": r["imsi"], "ICCID": r["iccid"], "Source record": source(r)} for r in rows]


def unique_proofs(rows):
    return len({r["source_sha"] for r in rows})


def sample_citation(rows):
    return source(rows[0])


def group_contacts(rows):
    found = defaultdict(list)
    for row in rows:
        found[row["peer"]].append(row)
    return found


def window_summary(start, end):
    if start is not None:
        return f"Window {stamp(start)} to {stamp(end)} (end exclusive). "
    return ""


def contacts(case, number, start=None, end=None, mode="contacts"):
    rows = calls_for(case, number, start, end)
    if mode == "night":
        rows = [r for r in rows if r["timestamp"].astimezone(IST).hour < 6]
    title = {"contacts": "Contact activity", "night": "Night activity", "calls": "Calls in the selected window"}[mode]
    if not rows:
        return Finding(title, window_summary(start, end) + "The available CDR records contain no matching calls for this number.")
    outgoing = sum(r["direction"] == "Outgoing" for r in rows)
    incoming = len(rows) - outgoing
    night = sum(r["timestamp"].astimezone(IST).hour < 6 for r in rows)
    durations = [r["duration_sec"] for r in rows if r["duration_sec"] is not None]
    ratio = f"{incoming / outgoing:.2f}:1" if outgoing else "undefined (zero outbound calls)"
    summary = (f"{window_summary(start, end)}{len(rows):,} calls for {number}: {incoming:,} incoming, "
               f"{outgoing:,} outgoing (incoming/outgoing {ratio}). {night:,} occurred between 00:00 and 06:00 IST. "
               f"Recorded duration totals {sum(durations):,} seconds across {len(durations):,} calls. "
               f"First {stamp(rows[0]['timestamp'])}. Last {stamp(rows[-1]['timestamp'])}.")
    if mode == "calls":
        return Finding(title, summary, call_evidence(rows), call_evidence(rows))
    ranking = []
    for peer, group in sorted(group_contacts(rows).items(), key=lambda item: (-len(item[1]), item[0])):
        n_out = sum(r["direction"] == "Outgoing" for r in group)
        n_night = sum(r["timestamp"].astimezone(IST).hour < 6 for r in group)
        present = [r["duration_sec"] for r in group if r["duration_sec"] is not None]
        flag = "Night-heavy (≥50%, 3+ calls)" if len(group) >= 3 and n_night * 2 >= len(group) and mode != "night" else ""
        first, last = group[0], group[-1]
        ranking.append({"Contact": peer, "Calls": len(group), "Incoming": len(group)-n_out, "Outgoing": n_out,
                        "Seconds": sum(present) if present else None, "Durations present": len(present),
                        "Night calls": n_night, "First (IST)": stamp(first["timestamp"]),
                        "Last (IST)": stamp(last["timestamp"]), "Pattern flag": flag,
                        "Source files": unique_proofs(group), "Source example": sample_citation(group)})
    lead = ranking[0]
    summary += f" Top contact {lead['Contact']} appeared in {lead['Calls']} calls ({lead['Source example']})."
    return Finding(title, summary, ranking, call_evidence(rows))


def count_calls(case, number, start, end, *, direction=None):
    rows = calls_for(case, number, start, end)
    if direction:
        rows = [row for row in rows if row["direction"] == direction]
    label = direction.lower() + " " if direction else ""
    evidence = call_evidence(rows)
    summary = window_summary(start, end) + (
        f"{number} has {len(rows):,} recorded {label}calls in the available CDRs." if rows else
        f"The available CDRs contain no matching {label}calls for {number}.")
    return Finding("Recorded call count", summary, evidence=evidence)


def call_boundaries(case, number, start, end, *, earliest, latest, direction, peer=None):
    rows = calls_for(case, number, start, end)
    if peer:
        rows = [row for row in rows if row["peer"] == peer]
    if direction:
        rows = [row for row in rows if row["direction"] == direction]
    label = "First and last" if earliest and latest else "First" if earliest else "Last"
    direction_text = f"{direction.lower()} " if direction else ""
    title = f"{label} recorded {direction_text}call"
    if not rows:
        scope = f"between {number} and {peer}" if peer else f"for {number}"
        return Finding(title, window_summary(start, end) +
                       f"The available records contain no matching {direction_text}calls {scope}.")
    bounds = {}
    if earliest:
        bounds[rows[0]["timestamp"]] = "First"
    if latest:
        when = rows[-1]["timestamp"]
        bounds[when] = "First and last" if when in bounds else "Last"
    chosen = [row for row in rows if row["timestamp"] in bounds]
    evidence = call_evidence(chosen)
    table = [{"Position": bounds[row["timestamp"]], "Other number": row["peer"], **record}
             for row, record in zip(chosen, evidence)]
    summary = window_summary(start, end)
    if len(chosen) == 1:
        row = chosen[0]
        verb = "called" if row["direction"] == "Outgoing" else "received a call from"
        duration = f" Duration {row['duration_sec']} seconds." if row["duration_sec"] is not None else ""
        summary += f"{number} {verb} {row['peer']} at {stamp(row['timestamp'])}.{duration} [{source(row)}]"
    else:
        scope = f"between {number} and {peer}" if peer else f"for {number}"
        summary += f"Recorded {direction_text}call {'boundaries' if len(bounds) > 1 else 'timestamp'} {scope}."
        if len(chosen) > len(bounds):
            summary += " Several records share a boundary timestamp. The available rows do not establish their order."
    return Finding(title, summary, table, evidence)


def common_contacts(case, first, second, start=None, end=None, *, outgoing_only=False):
    if first == second:
        return Finding("Common contacts", "Choose two different phone numbers.")
    first_rows, second_rows = (calls_for(case, p, start, end) for p in (first, second))
    direct_rows = [row for row in first_rows if row["peer"] == second]
    if outgoing_only:
        first_rows = [row for row in first_rows if row["direction"] == "Outgoing"]
        second_rows = [row for row in second_rows if row["direction"] == "Outgoing"]
    a, b = group_contacts(first_rows), group_contacts(second_rows)
    shared = (a.keys() & b.keys()) - {first, second}
    items, evidence = [], []
    for number in sorted(shared, key=lambda key: (-(len(a[key])+len(b[key])), key)):
        left, right = a[number], b[number]
        items.append({"Shared number": number, "Calls with A": len(left), "Calls with B": len(right),
                      "Distinct files": unique_proofs(left + right),
                      "A source example": sample_citation(left), "B source example": sample_citation(right)})
        for label, group in (("A", left), ("B", right)):
            evidence.extend({"Compared subject": label, **r} for r in call_evidence(group))
    direct = len(direct_rows)
    if not first_rows or not second_rows:
        direction = " outgoing" if outgoing_only else ""
        summary = f"The available CDR records do not contain{direction} calls for both selected numbers."
    else:
        comparison = (f"both called {len(shared)} third-party numbers" if outgoing_only
                      else f"share {len(shared)} third-party contacts")
        summary = f"{first} and {second} {comparison}. The logs contain {direct} direct calls between them."
    if items:
        summary += f" Highest combined recorded count: {items[0]['Shared number']}."
    # Keep direct-call claims and zero-overlap comparisons inspectable.
    if direct:
        evidence.extend({"Compared subject": "Direct A/B", **r} for r in call_evidence(direct_rows))
    if not items and not direct:
        evidence.extend({"Compared subject": label, **r} for label, group in (("A", first_rows), ("B", second_rows))
                        for r in call_evidence(group))
    return Finding("Common contacts", window_summary(start, end) + summary, items, evidence)


def observations(case, number, start=None, end=None):
    predicate = "COALESCE(observed_msisdn, caller_msisdn)=?"
    cdr = case.query(f"SELECT *, timestamp AS event_time, 'CDR' AS record_type FROM cdr_calls WHERE {predicate}", [number])
    ipdr = case.query("""SELECT *, session_start AS event_time, 'IPDR' AS record_type
                        FROM ipdr_cgnat WHERE caller_msisdn=?""", [number])
    return sorted([r for r in cdr + ipdr if (start is None or r["event_time"] >= start)
                   and (end is None or r["event_time"] < end)],
                  key=lambda r: (r["event_time"], r["source_sha"], r["source_locator"]))


def movement(case, number, start=None, end=None):
    by_id = defaultdict(list)
    for tower in case.all("tower_locations"):
        by_id[tower["tower_id"]].append(tower)
    events = [r for r in observations(case, number, start, end) if r["cell_tower_id"]]
    visits = []
    evidence = []
    previous = None
    for r in events:
        tower_id = r["cell_tower_id"]
        known = by_id[tower_id]
        coordinates = {(t["lat"], t["lon"]) for t in known}
        tower = known[0] if len(coordinates) == 1 else None
        if previous is None or previous["Tower ID"] != tower_id:
            previous = {"Visit": len(visits)+1, "Tower ID": tower_id,
                        "Tower": tower["tower_name"] if tower else tower_id,
                        "Latitude": tower["lat"] if tower else None, "Longitude": tower["lon"] if tower else None,
                        "First (IST)": stamp(r["event_time"]), "Last (IST)": None, "Observations": 0,
                        "First source": source(r), "Last source": None,
                        "Coordinates source": source(tower) if tower else
                        "Conflicting tower coordinates" if coordinates else "Tower coordinates unavailable"}
            visits.append(previous)
        previous["Last (IST)"] = stamp(r["event_time"])
        previous["Last source"] = source(r)
        previous["Observations"] += 1
        evidence.append({"Visit": previous["Visit"], "Time (IST)": stamp(r["event_time"]), "Number": number,
                         "Tower ID": tower_id, "Log": r["record_type"], "Source record": source(r),
                         "Coordinates source": previous["Coordinates source"]})
    mapped = sum(v["Latitude"] is not None for v in visits)
    if not events:
        summary = "The available records contain no serving tower observations for this number."
    else:
        frequencies = Counter(r["cell_tower_id"] for r in events)
        frequent, count = sorted(frequencies.items(), key=lambda item: (-item[1], item[0]))[0]
        summary = (f"{len(events)} logged observations grouped into {len(visits)} consecutive visits. "
                   f"{mapped} visits have coordinates. Most observed tower {frequent} ({count}). "
                   "These are serving tower observations, not a GPS route.")
    return Finding("Serving tower timeline", window_summary(start, end) + summary, visits, evidence)


def device_changes(case, number, start=None, end=None):
    events = observations(case, number, start, end)
    items, evidence = [], []
    for key, label in (("imei", "Handset IMEI"), ("imsi", "SIM IMSI"), ("iccid", "SIM ICCID")):
        seen = [r for r in events if r.get(key)]
        prior = None
        groups = defaultdict(list)
        for row in seen:
            groups[row["event_time"]].append(row)
        for timestamp, same_time in groups.items():
            current = same_time[0]
            if len({r[key] for r in same_time}) > 1:
                items.append({"Time (IST)": stamp(timestamp), "Identifier": label, "Event": "Conflicting observations",
                              "Previous": None, "Observed": ", ".join(sorted({r[key] for r in same_time})),
                              "Previous source": None, "Observed source": " | ".join(source(r) for r in same_time)})
                prior = None
            else:
                if prior is not None and prior[key] != current[key]:
                    items.append({"Time (IST)": stamp(timestamp), "Identifier": label, "Event": "Observed change",
                                  "Previous": prior[key], "Observed": current[key], "Previous source": source(prior),
                                  "Observed source": source(current)})
                prior = current
            evidence.extend({"Time (IST)": stamp(r["event_time"]), "Number": number, "Identifier": label,
                             "Value": r[key], "Log": r["record_type"], "Source record": source(r)} for r in same_time)
    counts = Counter(r["Identifier"] for r in items if r["Event"] == "Observed change")
    summary = (f"{counts['Handset IMEI']} IMEI, {counts['SIM IMSI']} IMSI and {counts['SIM ICCID']} ICCID changes "
               "between consecutive known observations. Missing identifiers are skipped.")
    if not evidence:
        summary = "The available records contain no handset or SIM identifiers for this number."
    return Finding("Handset and SIM observations", window_summary(start, end)+summary,
                   sorted(items, key=lambda r: (r["Time (IST)"], r["Identifier"])), evidence)


def ipdr_activity(case, number=None, start=None, end=None):
    conditions, params = [], []
    if number:
        conditions.append("caller_msisdn=?")
        params.append(number)
    if start:
        conditions.append("session_start>=?")
        params.append(start)
    if end:
        conditions.append("session_start<?")
        params.append(end)
    where = " WHERE " + " AND ".join(conditions) if conditions else ""
    records = case.query("SELECT * FROM ipdr_cgnat" + where + " ORDER BY session_start,source_sha,source_locator", params)
    rows = [{"Start (IST)": stamp(r["session_start"]), "End (IST)": stamp(r["session_end"]),
             "Subscriber": r["caller_msisdn"], "Public IP": r["public_ip"], "Source port": r["source_port"],
             "Protocol": r["protocol"], "Supplied application": r["application"], "Supplied service": r["service"],
             "Destination host": r["destination_host"], "Source record": source(r)} for r in records]
    labelled = sum(bool(r["application"] or r["service"]) for r in records)
    summary = (f"{len(rows)} recorded IP sessions. {labelled} have an application or service label supplied by the source. "
               "Ports and hostnames alone do not establish which app was used.") if rows else "No matching IP sessions in the available records."
    return Finding("IPDR service indicators", window_summary(start, end)+summary, rows, rows)


def case_summary(case, number, start=None, end=None):
    parts = [contacts(case, number, start, end), movement(case, number, start, end),
             device_changes(case, number, start, end), ipdr_activity(case, number, start, end)]
    overview = [{"Section": item.title, "Finding": item.summary,
                 "Source example": next((v for r in item.evidence for k,v in r.items() if k == "Source record"), "No matching source row")}
                for item in parts]
    evidence = [{"Section": item.title, **row} for item in parts for row in item.evidence]
    return Finding("Case summary", f"Evidence summary for {number}. Review the underlying records before recording a conclusion.",
                   overview, evidence)


def explain_graph(case, number, start=None, end=None):
    finding = contacts(case, number, start, end)
    return Finding("Contact graph interpretation",
                   "Each edge represents recorded calls between two numbers. Edge weight is the observed call count. "
                   "The table explains the underlying connection counts. " + finding.summary, finding.rows, finding.evidence)


TASKS = {"contacts": contacts, "common": common_contacts, "movement": movement,
         "device": device_changes, "ipdr": ipdr_activity, "summary": case_summary, "explain": explain_graph}

HINDI_NAMES = {"रोहन मेहता": "rohan mehta", "अमन वर्मा": "aman verma", "विकाश शर्मा": "vikash sharma",
               "विकास शर्मा": "vikash sharma", "नेहा सिंह": "neha singh", "रजत कुमार": "rajat kumar"}
NUMBER = re.compile(r"(?<!\w)(?:\+91[ -]?)?\d{5}[- ]?\d{5}(?!\w)")
INTENT_RULES = (
    ("common", "common number|common contact|shared contact|shared number|dono.*(?:same|common)|साझा|समान नंबर"),
    ("device", r"imei|imsi|iccid|sim\s*(?:change|switch|rotation)|handset|सिम|हैंडसेट"),
    ("ipdr", "ipdr|service indicator|app usage|application usage|ऐप|आईपीडीआर"),
    ("summary", "summari[sz]e|summary|सारांश|case overview"),
    ("explain", "explain.*(?:graph|chart|network)|interpret.*(?:graph|chart)|ग्राफ समझा|नेटवर्क समझा"),
    ("night", "night|last night|raat|रात"),
    ("movement", "timeline|trajectory|movement|repeated tower|tower sequence|टावर क्रम|टावर टाइमलाइन|लोकेशन क्रम"),
    ("contacts", "frequent contact|top contact|most called|call count|call duration|contact pattern|unusual contact|incoming|outgoing|सबसे ज़्यादा|सबसे ज्यादा|अधिक कॉल"),
    ("calls", r"time window|between|calls on|samay|समय|\d{2}:\d{2}"),
)


def boundary_request(question):
    if not re.search(r"\bcalls?\b|\bcalled\b|\bcalling\b|कॉल|फोन", question):
        return None
    earliest = bool(re.search(r"\bfirst(?!\s+\d)\b|\bearliest\b|\bpehl[ai]e?\b|पहली|पहला|सबसे पहले", question))
    latest = bool(re.search(r"\blast(?![\s-]+(?:night|evening|\d+)\b)\b|\blastly\b|\blatest\b|"
                            r"\bmost recent\b|\baakhri\b|आख[़ि]*री|अंतिम", question))
    if not (earliest or latest):
        return None
    incoming = re.search(r"\bincoming\b|\breceiv(?:e|ed|es|ing)\b|\bwho\s+(?:last\s+|first\s+)?called\b|"
                         r"\bcalled\s+(?:the\s+)?suspect\b|किसने|कॉल आई", question)
    outgoing = re.search(r"\boutgoing\b|\boutbound\b|\b(?:who|whom|what|which)\b.{0,64}\bdid\b.{0,64}\bcall(?:ed)?\b|"
                         r"\b(?:call(?:ed)?|dial(?:ed|led)?)\s+to\b|किसे|किसको|किस नंबर पर", question)
    direction = "Incoming" if incoming and not outgoing else "Outgoing" if outgoing and not incoming else None
    return earliest, latest, direction


CALL_COUNT = re.compile(r"\bhow many\b.{0,24}\bcalls?\b|\bnumber of calls\b|कितनी कॉल|कितने फोन|kitn[ei].{0,16}calls?")
JOINT_CALL = re.compile(r"\b(?:both|dono)\s+(?:call(?:ed)?|dial(?:ed|led)?)\b|called by both")


def question_window(case, text, numbers):
    clocks = re.findall(r"(?<![\dT])\b\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?\b", text)
    dates = re.findall(r"\b20\d{2}-\d{2}-\d{2}\b", text)
    if not dates and not clocks:
        return None, None
    if len(dates) > 2 or (clocks and len(clocks) != 2):
        raise ValueError("Give one date or a start and end time, for example 2026-01-14 02:00 to 04:00 IST.")
    if not dates:
        observed = {r["timestamp"].astimezone(IST).date().isoformat() for number in numbers for r in calls_for(case, number)}
        if len(observed) != 1:
            raise ValueError("Include an ISO date to disambiguate the selected time window.")
        dates = list(observed)
    first = datetime.fromisoformat(dates[0]).date()
    last = datetime.fromisoformat(dates[-1]).date()
    start = datetime.combine(first, time.fromisoformat(clocks[0]) if clocks else time.min, IST)
    end = datetime.combine(last + (timedelta(days=1) if not clocks else timedelta()), time.fromisoformat(clocks[1]) if clocks else time.min, IST)
    if clocks and len(dates) == 1 and end < start:
        end += timedelta(days=1)
    if end <= start:
        raise ValueError("The end of the window must be after its start.")
    return start, end


def answer(case, question, active=None, compare=None, predicted=None):
    lower = question.casefold()
    # Keep named-site tower CDR queries and bank trails on their dedicated handlers.
    if re.search("bank|money trail|बैंक|लेनदेन|transfer|payment|ledger", lower):
        return None
    if (re.search("tower|टावर", lower) and re.search("call|कॉल", lower)
            and not re.search("repeat|sequence|timeline|क्रम|टाइमलाइन", lower)):
        return None
    boundary = boundary_request(lower)
    is_count = bool(CALL_COUNT.search(lower)) and not re.search(r"night|raat|रात", lower)
    joint_call = bool(JOINT_CALL.search(lower))
    kind = ("boundary" if boundary else "common" if joint_call else "count" if is_count else
            next((label for label, expression in INTENT_RULES if re.search(expression, lower)), predicted))
    if kind not in {*TASKS, "night", "calls", "boundary", "count"}:
        return None
    listed = names(case)
    if case.demo:
        for local, english in HINDI_NAMES.items():
            if local in lower:
                lower += " " + english
    mentions = []
    for match in NUMBER.finditer(question):
        digits = re.sub(r"\D", "", match.group())
        mentions.append((match.start(), "+" + ("91" + digits if len(digits) == 10 else digits)))
    for name, values in listed.items():
        match = re.search(r"(?<!\w)" + re.escape(name) + r"(?!\w)", lower)
        if match:
            if len(set(values)) != 1:
                return Finding("Select a subject", f"More than one profile is named {name}. Use the phone number instead.")
            mentions.append((match.start(), values[0]))
    matched = list(dict.fromkeys(number for _, number in sorted(mentions)))
    if not matched and active:
        matched.append(active)
    if kind == "common" and len(matched) == 1 and compare and compare != matched[0]:
        matched.append(compare)
    valid_counts = (1, 2) if kind == "boundary" else (2,) if kind == "common" else (1,)
    if len(matched) not in valid_counts:
        return Finding("Select a subject", "Choose two different case numbers to compare." if kind == "common"
                       else "Select a case number or include one complete phone number or profile name in your question.")
    relative_night = re.search(r"last night|last evening|yesterday|pichli raat|पिछली रात|कल रात", lower)
    if relative_night and not re.search(r"\b20\d{2}-\d{2}-\d{2}\b", lower):
        return Finding("Date needed", "Enter a date for a night activity question. The night window is 00:00–06:00 IST.")
    start, end = question_window(case, question, matched)
    if boundary:
        earliest, latest, direction = boundary
        peer = matched[1] if len(matched) == 2 else None
        return call_boundaries(case, matched[0], start, end, earliest=earliest, latest=latest, direction=direction, peer=peer)
    if kind == "count":
        incoming = re.search(r"\bincoming\b|\breceiv\w*\b|कॉल आईं?", lower)
        outgoing = re.search(r"\boutgoing\b|\bmake\b|\bmade\b|कॉल कीं?", lower)
        direction = "Incoming" if incoming and not outgoing else "Outgoing" if outgoing and not incoming else None
        return count_calls(case, matched[0], start, end, direction=direction)
    if kind == "common":
        return common_contacts(case, *matched, start, end, outgoing_only=joint_call)
    if kind in {"night", "calls"}:
        if kind == "calls" and start is None:
            return Finding("Time window needed", "Supply an ISO date and two times in IST.")
        return contacts(case, matched[0], start, end, mode=kind)
    return TASKS[kind](case, *matched, start, end)


def build_xlsx(title, findings):
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    workbook = Workbook()
    cover = workbook.active
    cover.title = "Review summary"
    cover.append([title])
    cover.append(["Status", "Draft for officer review"])
    for finding in findings:
        cover.append([finding.title, finding.summary])
    cover.column_dimensions["A"].width = 37
    cover.column_dimensions["B"].width = 100
    for row in list(cover)[2:]:
        row[1].alignment = Alignment(wrap_text=True, vertical="top")
        cover.row_dimensions[row[1].row].height = 55
    for index, finding in enumerate(findings, 1):
        for label, records in (("Results", finding.rows), ("Sources", finding.evidence)):
            if not records:
                continue
            sheet = workbook.create_sheet(f"{index:02} {label}")
            columns = list(dict.fromkeys(key for row in records for key in row))
            sheet.append(columns)
            for row in records:
                sheet.append([row.get(key) for key in columns])
            sheet.freeze_panes = "A2"
            sheet.auto_filter.ref = sheet.dimensions
            for cell in sheet[1]:
                cell.fill = PatternFill("solid", fgColor="284538")
                cell.font = Font(color="FFFFFF", bold=True)
                sheet.column_dimensions[cell.column_letter].width = 54 if "Source" in str(cell.value) else 25
    for sheet in workbook:
        # Uploaded values remain text, including strings that resemble formulas.
        for row in sheet:
            for cell in row:
                if cell.data_type == "f":
                    cell.data_type = "s"
    buffer = io.BytesIO()
    workbook.save(buffer)
    return buffer.getvalue()


def build_pdf(title, findings):
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen.canvas import Canvas
    buffer = io.BytesIO()
    page = Canvas(buffer, pagesize=A4)
    page.setTitle(title)
    width, height = A4
    line_y = height - 58
    index = 1

    def write(text, size=10, bold=False):
        nonlocal line_y, index
        for line in textwrap.wrap(str(text), width=91 if size <= 10 else 73, break_long_words=True) or [""]:
            if line_y < 59:
                page.setFont("Helvetica", 8)
                page.drawRightString(width-42, 34, f"Page {index}")
                page.showPage()
                index += 1
                line_y = height - 58
            page.setFont("Helvetica-Bold" if bold else "Helvetica", size)
            page.drawString(42, line_y, line)
            line_y -= size + 5

    write(title, 16, True)
    write("Draft investigation report for officer review.", 11)
    for finding in findings:
        line_y -= 12
        write(finding.title, 13, True)
        write(finding.summary)
        if len(finding.rows) > 10 or len(finding.evidence) > 15:
            write("This PDF includes up to 10 findings and 15 source rows per section. The Excel export contains the full result.")
        for row in finding.rows[:10]:
            write(" | ".join(f"{key}: {value}" for key, value in row.items() if value is not None))
        for row in finding.evidence[:15]:
            proof = row.get("Source record")
            if proof:
                write(proof, 9)
    page.setFont("Helvetica", 8)
    page.drawRightString(width-42, 34, f"Page {index}")
    page.save()
    return buffer.getvalue()
