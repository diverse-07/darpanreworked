"""Local JSON bridge for the React workstation. Requests travel over stdin."""
import json
import os
import re
import sys
from dataclasses import asdict
from pathlib import Path

from station_vault import Station

IDENTITY = {"username": "workspace-service", "role": "investigator"}
LABEL = "Darpan Reworked workspace"


def station_request(operation, data):
    root = Path(os.getenv("DARPAN_REWORKED_HOME", Path.home() / ".darpan-reworked"))
    station = Station(root, os.getenv("DARPAN_KEY_FILE"))
    if operation == "authenticate":
        return station.authenticate(data["username"], data["password"])
    cases = [key for key, label in station.list_cases(IDENTITY) if label == LABEL]
    if operation == "open":
        if not cases:
            key, revision = station.create(IDENTITY, LABEL, data)
            return {"key": key, "revision": revision, "value": data}
        revision, value = station.load(IDENTITY, cases[0])
        return {"key": cases[0], "revision": revision, "value": value}
    if operation == "save":
        if data["key"] not in cases:
            raise ValueError("Workspace does not exist")
        return station.save(IDENTITY, data["key"], data["revision"], data["value"], "import")
    raise ValueError("Unknown operation")


def local_answer(data):
    from app import Case, classify_question
    from telecom_analysis import answer, subjects

    case_data = data["caseFile"]
    question = data["question"]
    case = Case(demo=data["demo"])
    sources = {source["id"]: source["sha256"] for source in case_data["sources"]}
    sources_by_file = {source["fileName"]: source["sha256"] for source in case_data["sources"]}

    def meta(row):
        return {
            "source_sha": sources.get(row.get("sourceId"), sources_by_file.get(row.get("sourceFile"), "0" * 64)),
            "source_file": row.get("sourceFile") or "Case identity register",
            "source_locator": f'Row #{row.get("rowNumber") or 0}',
        }

    calls = [dict(meta(row), record_id=row["id"], telco=row["operator"],
                  timestamp=row["timestampIso"], caller_msisdn=row["caller"], callee_msisdn=row["callee"],
                  duration_sec=row["durationSec"], imei=row.get("imei"), imsi=row.get("imsi"),
                  iccid=row.get("iccid"), cell_tower_id=row.get("cellTowerId"), observed_msisdn=row["observedMsisdn"])
             for row in case_data["cdrs"] if row["callType"] not in ("SMS_OUT", "SMS_IN")]
    sessions = [dict(meta(row), record_id=row["id"], telco=row["operator"],
                     session_start=row["sessionStartIso"], session_end=row.get("sessionEndIso"),
                     caller_msisdn=row["msisdn"], public_ip=row["publicIp"], protocol=row["protocol"],
                     cell_tower_id=row.get("cellTowerId"), imei=row.get("imei"), imsi=row.get("imsi"),
                     iccid=row.get("iccid"), source_port=row.get("sourcePort"),
                     alloc_port_start=row.get("allocPortStart"), alloc_port_end=row.get("allocPortEnd"),
                     application=row.get("application"), service=row.get("service"),
                     destination_host=row.get("destinationHost"), session_duration_sec=row.get("sessionDurationSec"))
                for row in case_data["ipdrs"]]
    profiles = [dict(meta(row), suspect_id=row["suspectId"], name=row["name"], phone=row["phone"],
                     known_imeis=row["knownImeis"], base_location=row["baseLocation"], prior_firs=row["priorFirs"])
                for row in case_data["suspects"]]
    towers = [dict(meta(row), tower_id=row["towerId"], tower_name=row["towerName"],
                   lat=row["lat"], lon=row["lon"], azimuth_degrees=row["azimuthDegrees"])
              for row in case_data["towers"]]
    for table, rows in (("cdr_calls", calls), ("ipdr_cgnat", sessions),
                        ("suspect_master", profiles), ("tower_locations", towers)):
        if rows:
            case._insert(table, rows)
    try:
        numbers = subjects(case)
        selected = list(dict.fromkeys([p["phone"] for p in case_data["suspects"]] + numbers))
        active = data.get("active") or next(iter(selected), None)
        compare = data.get("compare") or next((n for n in selected if n != active), None)
        finding = answer(case, question, active, compare, predicted=classify_question(question))
        return asdict(finding) if finding else None
    finally:
        case.db.close()


if __name__ == "__main__":
    try:
        operation = sys.argv[1]
        data = json.load(sys.stdin)
        result = local_answer(data) if operation == "answer" else station_request(operation, data)
        print(json.dumps({"value": result}, ensure_ascii=True, default=str))
    except (ValueError, KeyError, PermissionError) as error:
        print(json.dumps({"error": str(error)}, ensure_ascii=True))
