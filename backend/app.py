"""DARPAN FORENSICS | offline synthetic-case workstation for PS03.

Run: streamlit run app.py --server.address 127.0.0.1 --browser.gatherUsageStats false --theme.base dark
Optional upload readers: openpyxl (XLSX), pypdf (text-based tabular PDF).
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import html
import io
import ipaddress
import json
import math
import os
import re
import sys
import time
import unicodedata
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path, PurePath
from uuid import NAMESPACE_URL, uuid5

os.environ.setdefault("STREAMLIT_BROWSER_GATHER_USAGE_STATS", "false")

import duckdb
import networkx as nx
import streamlit as st
import torch
import darpan_models as models
import station_vault as vault
import telecom_analysis as telecom

IST = timezone(timedelta(hours=5, minutes=30), "IST")
UTC = timezone.utc
DEMO_DATE = "2026-01-14"
DRIFT_MS = 50
MAX_BYTES = 32 * 1024 * 1024
MAX_ROWS = 100_000
VERSION = "3.0"
BSA = "https://www.indiacode.nic.in/indiacode/bitstream/123456789/20063/1/aa202347.pdf"

SCHEMAS = {
    "cdr_calls": dict(record_id="VARCHAR", telco="VARCHAR", timestamp="TIMESTAMPTZ",
                      caller_msisdn="VARCHAR", callee_msisdn="VARCHAR", duration_sec="INTEGER",
                      imei="VARCHAR", imsi="VARCHAR", cell_tower_id="VARCHAR",
                      iccid="VARCHAR", observed_msisdn="VARCHAR"),
    "ipdr_cgnat": dict(record_id="VARCHAR", telco="VARCHAR", session_start="TIMESTAMPTZ",
                       session_end="TIMESTAMPTZ", caller_msisdn="VARCHAR", imei="VARCHAR",
                       imsi="VARCHAR", public_ip="VARCHAR", source_port="INTEGER",
                       alloc_port_start="INTEGER", alloc_port_end="INTEGER", protocol="VARCHAR",
                       cell_tower_id="VARCHAR", iccid="VARCHAR", application="VARCHAR",
                       service="VARCHAR", destination_host="VARCHAR", session_duration_sec="INTEGER"),
    "bank_ledger": dict(txn_id="VARCHAR", timestamp="TIMESTAMPTZ", sender_name="VARCHAR",
                        receiver_name="VARCHAR", sender_acc="VARCHAR", receiver_acc="VARCHAR",
                        amount_inr="DECIMAL(19,2)", status="VARCHAR"),
    "suspect_master": dict(suspect_id="VARCHAR", name="VARCHAR", phone="VARCHAR",
                           known_imeis="VARCHAR[]", base_location="VARCHAR", prior_firs="VARCHAR[]"),
    "tower_locations": dict(tower_id="VARCHAR", tower_name="VARCHAR", lat="DOUBLE", lon="DOUBLE",
                            azimuth_degrees="DOUBLE"),
}
REQUIRED = {
    "cdr_calls": "timestamp caller_msisdn callee_msisdn",
    "ipdr_cgnat": "session_start public_ip",
    "bank_ledger": "timestamp sender_acc receiver_acc amount_inr",
    "suspect_master": "name phone",
    "tower_locations": "tower_id lat lon",
}
ALIASES = {
    "record_id": "call_id session_id event_id",
    "txn_id": "transaction_id utr reference_number ref_no",
    "telco": "operator provider carrier service_provider",
    "timestamp": "timestamp_ist time call_start call_start_time call_time call_date_time transaction_date transaction_time txn_date txn_time datetime date_time date",
    "session_start": "start_time allocation_start session_start_time start_timestamp timestamp session_time event_time",
    "session_end": "end_time allocation_end session_end_time end_timestamp",
    "caller_msisdn": "caller calling_number calling_party_number a_party a_number anumber msisdn mobile_number subscriber_number source_msisdn",
    "callee_msisdn": "callee called_number called_party_number b_party b_number bnumber destination_msisdn",
    "duration_sec": "duration duration_seconds call_duration billsec call_duration_secs",
    "imei": "device_imei handset_imei",
    "imsi": "subscriber_imsi",
    "iccid": "sim_iccid sim_serial_number sim_serial",
    "observed_msisdn": "served_msisdn device_msisdn tower_msisdn",
    "cell_tower_id": "tower_id cell_id cellid serving_cell first_cell_id",
    "public_ip": "external_ip public_ipv4 nat_ip nat_public_ip",
    "source_port": "public_port external_port nat_port",
    "alloc_port_start": "port_start start_port first_port",
    "alloc_port_end": "port_end end_port last_port",
    "protocol": "transport transport_protocol",
    "application": "app app_name application_name",
    "service": "service_name service_indicator",
    "destination_host": "destination_hostname domain hostname server_name",
    "session_duration_sec": "session_duration session_seconds duration_sec duration_seconds",
    "phone": "msisdn mobile mobile_number phone_number",
    "name": "suspect_name full_name",
    "known_imeis": "imeis devices",
    "prior_firs": "fir firs fir_numbers",
    "sender_name": "remitter payer debit_name",
    "receiver_name": "beneficiary payee credit_name",
    "sender_acc": "sender_account debit_account from_account remitter_account",
    "receiver_acc": "receiver_account credit_account to_account beneficiary_account",
    "amount_inr": "amount transaction_amount inr",
    "tower_id": "cell_id cell_tower_id site_id",
    "tower_name": "cell_name site_name",
    "lat": "latitude",
    "lon": "longitude lng",
    "azimuth_degrees": "azimuth bearing",
}
ATTACHMENTS = {".wav", ".mp3", ".m4a", ".ogg", ".flac", ".png", ".jpg", ".jpeg", ".webp"}
SOURCE_META = "source_sha VARCHAR, source_file VARCHAR, source_locator VARCHAR"
FEATURE_NAMES = ("Outgoing calls", "Night call ratio", "IMEI switches", "Ledger inflow (INR)",
                 "Shared tower observations", "Degree centrality")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(obj):
    def encode(value):
        if isinstance(value, datetime):
            return value.astimezone(UTC).isoformat(timespec="microseconds")
        if isinstance(value, Decimal):
            return str(value)
        raise TypeError(type(value).__name__)
    return json.dumps(obj, default=encode, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def esc(value):
    return html.escape(str(value), quote=True)


def as_time(value):
    if isinstance(value, (float, int)):
        raise ValueError("Use dates formatted as ISO-8601 text or XLSX date cells")
    if isinstance(value, datetime):
        result = value
    else:
        value = str(value or "").strip()
        if re.match(r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}", value):
            result = datetime.fromisoformat(value.replace(" IST", "+05:30").replace(" UTC", "+00:00"))
        else:
            formats = (f"{date} {clock}" for date in ("%d/%m/%Y", "%d-%m-%Y")
                       for clock in ("%H:%M:%S.%f", "%H:%M:%S", "%H:%M"))
            for pattern in formats:
                try:
                    result = datetime.strptime(value, pattern)
                    break
                except ValueError:
                    pass
            else:
                raise ValueError("Provide a full timestamp in ISO-8601 or DD/MM/YYYY HH:MM:SS format")
    return (result if result.tzinfo else result.replace(tzinfo=IST)).astimezone(UTC)


def display_time(value):
    return value.astimezone(IST).isoformat(sep=" ", timespec="milliseconds") + " IST"


def phone(value):
    digits = re.sub(r"\D", "", str(value or ""))
    if len(digits) == 10:
        digits = "91" + digits
    if not 7 <= len(digits) <= 15:
        raise ValueError("Invalid telephone identifier")
    return "+" + digits


def header_key(value):
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").lower()).strip("_")


def list_field(value):
    if not value:
        return []
    if isinstance(value, str):
        value = json.loads(value) if value.lstrip().startswith("[") else re.split(r"[|;,]", value)
    if not isinstance(value, list):
        raise ValueError("Expected a list of identifiers")
    return [str(item).strip() for item in value if str(item).strip()]


def normalized(table, row, digest, name, locator, *, mapping=None, operator=None, observation="caller"):
    schema = SCHEMAS[table]
    values = {}
    for key, dtype in schema.items():
        mapped = (mapping or {}).get(key)
        aliases = (mapped,) if mapped else (key, *ALIASES.get(key, "").split())
        raw = next((row[alias] for alias in aliases if alias in row and row[alias] not in (None, "")), None)
        if key == "telco" and raw is None:
            raw = operator
        if table == "cdr_calls" and key == "timestamp":
            date = row.get("call_date")
            clock = row.get("call_time")
            if not mapped and date and clock:
                raw = f"{date} {clock}"
        if raw is None:
            values[key] = [] if dtype.endswith("[]") else None
        elif dtype == "TIMESTAMPTZ":
            values[key] = as_time(raw)
        elif dtype == "INTEGER":
            numeric = Decimal(str(raw))
            if not numeric.is_finite() or numeric != numeric.to_integral_value():
                raise ValueError(f"{key} must be an integer")
            values[key] = int(numeric)
        elif dtype == "DOUBLE":
            values[key] = float(raw)
            if not math.isfinite(values[key]):
                raise ValueError(f"{key} must be finite")
        elif dtype.startswith("DECIMAL"):
            amount = Decimal(str(raw).replace(",", "").replace("₹", "").strip())
            if not amount.is_finite() or not 0 < amount < 10**17 or amount != amount.quantize(Decimal(".01")):
                raise ValueError("Amount must be positive, with at most two decimal places")
            values[key] = amount.quantize(Decimal(".01"))
        elif dtype.endswith("[]"):
            values[key] = list_field(raw)
        else:
            if key in {"imei", "imsi", "iccid", "sender_acc", "receiver_acc"} and isinstance(raw, (int, float)):
                raise ValueError(f"Format {key} as text to preserve identifier digits")
            values[key] = str(raw).strip() or None

    missing = [key for key in REQUIRED[table].split() if values[key] is None]
    if missing:
        raise ValueError("Missing " + ", ".join(missing))
    for key in ("phone", "caller_msisdn", "callee_msisdn", "observed_msisdn"):
        if values.get(key):
            values[key] = phone(values[key])
    if "telco" in values and values["telco"]:
        provider = header_key(values["telco"])
        values["telco"] = {"reliance_jio": "Jio 5G", "jio": "Jio 5G", "jio_5g": "Jio 5G",
                           "bharti_airtel": "Airtel", "airtel": "Airtel", "bsnl": "BSNL",
                           "vodafone_idea": "Vi", "vodafone": "Vi", "vi": "Vi"}.get(provider, values["telco"])
    for key in ("sender_acc", "receiver_acc", "cell_tower_id", "tower_id"):
        if values.get(key):
            values[key] = values[key].upper()
    if values.get("duration_sec") is not None and values["duration_sec"] < 0:
        raise ValueError("Call duration cannot be negative")
    if table == "cdr_calls" and not values["observed_msisdn"]:
        values["observed_msisdn"] = values["callee_msisdn" if observation == "callee" else "caller_msisdn"]
    if table == "ipdr_cgnat":
        values["public_ip"] = str(ipaddress.IPv4Address(values["public_ip"]))
        low, high, port = (values[key] for key in ("alloc_port_start", "alloc_port_end", "source_port"))
        if low is None and high is None:
            low = high = port
        if low is None or high is None or not 1 <= low <= high <= 65535:
            raise ValueError("Provide a valid translated source port or inclusive allocation range")
        if port is not None and not low <= port <= high:
            raise ValueError("Source port falls outside the allocation block")
        elapsed = values["session_duration_sec"]
        if elapsed is not None and elapsed < 0:
            raise ValueError("Session duration cannot be negative")
        if values["session_end"] is None:
            values["session_end"] = values["session_start"] + timedelta(seconds=elapsed or 0)
        if values["session_end"] < values["session_start"]:
            raise ValueError("Session ends before it starts")
        if not any(values[key] for key in ("caller_msisdn", "imsi", "imei")):
            raise ValueError("Allocation has no subscriber or device identifier")
        protocol = (values["protocol"] or "").upper()
        values.update(alloc_port_start=low, alloc_port_end=high, protocol={"6": "TCP", "17": "UDP"}.get(protocol, protocol) or None)
    if table == "tower_locations":
        angle = values["azimuth_degrees"]
        if not (-90 <= values["lat"] <= 90 and -180 <= values["lon"] <= 180 and (angle is None or 0 <= angle < 360)):
            raise ValueError("Invalid tower coordinates or azimuth")
        values["tower_name"] = values["tower_name"] or values["tower_id"]
    id_key = next(iter(schema))
    values[id_key] = values[id_key] or str(uuid5(NAMESPACE_URL, f"{digest}/{table}/{locator}"))
    return dict(values, source_sha=digest, source_file=name, source_locator=locator)


def table_records(headers, records):
    keys = [header_key(item) for item in headers]
    if not any(keys) or len(set(filter(None, keys))) != len(list(filter(None, keys))):
        raise ValueError("Headers must be present and unique")
    for locator, cells in records:
        if not any(value not in (None, "") for value in cells):
            continue
        if any(value not in (None, "") for value in cells[len(keys):]):
            raise ValueError(f"{locator} has fields beyond its headers")
        yield locator, {key: value for key, value in zip(keys, cells) if key}


def delimited(text, delimiter=None, page=None):
    if delimiter is None:
        try:
            delimiter = csv.Sniffer().sniff(text[:8192], delimiters=",;\t|").delimiter
        except csv.Error:
            delimiter = ","
    reader = csv.reader(io.StringIO(text, newline=""), delimiter=delimiter, strict=True)
    headers = next(reader, [])
    def records():
        while True:
            start = reader.line_num + 1
            cells = next(reader, None)
            if cells is None:
                break
            end = reader.line_num
            position = f"Row #{start:,}" if start == end else f"Rows #{start:,}–{end:,}"
            yield (f"Page {page}, extracted {position.lower()}" if page else position), cells
    yield from table_records(headers, records())


def read_upload(name, raw):
    suffix = PurePath(name).suffix.lower()
    if suffix in {".csv", ".tsv", ".psv", ".txt"}:
        return delimited(raw.decode("utf-8-sig"), {".tsv": "\t", ".psv": "|"}.get(suffix))
    if suffix in {".json", ".jsonl"}:
        def json_rows():
            if suffix == ".jsonl":
                rows = ((f"Line #{num:,}", json.loads(line))
                        for num, line in enumerate(raw.decode("utf-8-sig").splitlines(), 1) if line.strip())
            else:
                items = json.loads(raw)
                if not isinstance(items, list):
                    raise ValueError("JSON must contain an array of objects")
                rows = ((f"Item #{num:,}", item) for num, item in enumerate(items, 1))
            for locator, row in rows:
                if not isinstance(row, dict):
                    raise ValueError(f"{locator} must be an object")
                keys = [header_key(key) for key in row]
                if not all(keys) or len(set(keys)) != len(keys):
                    raise ValueError(f"{locator} has empty or conflicting keys")
                yield locator, dict(zip(keys, row.values()))
        return json_rows()
    if suffix == ".xlsx":
        def xlsx_rows():
            try:
                from openpyxl import load_workbook
            except ImportError as error:
                raise ValueError("Install openpyxl from the offline wheelhouse for XLSX") from error
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                if sum(entry.file_size for entry in archive.infolist()) > 128 * 1024 * 1024:
                    raise ValueError("Expanded workbook exceeds the 128 MiB limit")
            book = load_workbook(io.BytesIO(raw), read_only=True, data_only=True)
            try:
                for sheet in book.worksheets:
                    lines = sheet.values
                    headers = next(lines, [])
                    if not any(headers):
                        continue
                    yield from table_records(headers, ((f"Sheet {sheet.title}, Row #{i:,}", cells)
                                                        for i, cells in enumerate(lines, 2)))
            finally:
                book.close()
        return xlsx_rows()
    if suffix == ".pdf":
        def pdf_rows():
            try:
                from pypdf import PdfReader
            except ImportError as error:
                raise ValueError("Install pypdf from the offline wheelhouse for PDF") from error
            document = PdfReader(io.BytesIO(raw), strict=True)
            for page_no, page in enumerate(document.pages, 1):
                page_text = page.extract_text(extraction_mode="layout") or ""
                if not page_text.strip():
                    raise ValueError(f"Page {page_no} has no selectable text")
                if re.search(r"[,|;\t]", page_text.strip().splitlines()[0]):
                    yield from delimited(page_text.strip(), page=page_no)
                else:
                    lines = page_text.strip("\n").splitlines()
                    split = lambda line: re.split(r"\s{2,}", line.strip())
                    yield from table_records(split(lines[0]), ((f"Page {page_no}, extracted line {i}", split(line))
                                                               for i, line in enumerate(lines[1:], 2)))
        return pdf_rows()
    raise ValueError("Unsupported structured file")


def proof(row):
    return f"[Proof: {row['source_file']} {row['source_locator']} · SHA-256 {row['source_sha'][:12]}]"


class Case:
    def __init__(self, demo=False):
        self.demo = demo
        self.db = duckdb.connect(":memory:", config={"enable_external_access": "false"})
        self.db.execute("SET threads=2")
        self.db.execute("SET TimeZone='UTC'")
        for table, schema in SCHEMAS.items():
            fields = ", ".join(f'"{key}" {kind}' for key, kind in schema.items())
            self.db.execute(f"CREATE TABLE {table} ({fields}, {SOURCE_META})")
        self.sources = {}
        self.events = []
        self.append_event("case_opened", {"mode": "synthetic" if demo else "local"})
        self.analysis = None
        self.review = None
        self.station = None
        self.identity = None
        self.case_id = None
        self.revision = None

    def append_event(self, action, payload):
        prior = self.events[-1]["hash"] if self.events else "0" * 64
        event = dict(index=len(self.events) + 1, at=datetime.now(UTC), action=action, payload=payload, previous=prior)
        self.events.append(dict(event, hash=sha(canonical(event))))

    def activity(self, action, **details):
        if self.station:
            self.station.log(self.identity["username"], action, case_id=self.case_id, **details)
        else:
            self.append_event(action, details)

    def payload(self):
        return json.loads(canonical({
            "tables": {table: self.all(table) for table in SCHEMAS},
            "sources": {digest: dict(metadata, raw=base64.b64encode(metadata["raw"]).decode())
                        for digest, metadata in self.sources.items()},
            "events": self.events, "review": self.review,
        }))

    @classmethod
    def from_payload(cls, payload):
        case = cls()
        for table, rows in payload["tables"].items():
            if table in SCHEMAS and rows:
                case._insert(table, rows)
        case.sources = {digest: dict(meta, raw=base64.b64decode(meta["raw"]))
                        for digest, meta in payload["sources"].items()}
        case.events = payload["events"]
        case.review = payload.get("review")
        return case

    def key(self, label):
        return f"case_{self.case_id or 'sample'}_{label}"

    def save(self, action):
        if self.station:
            self.revision = self.station.save(self.identity, self.case_id, self.revision, self.payload(), action)

    def query(self, sql, args=None):
        cursor = self.db.execute(sql, args or [])
        columns = [column[0] for column in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def all(self, table):
        if table not in SCHEMAS:
            raise ValueError("Unknown table")
        return self.query(f"SELECT * FROM {table} ORDER BY source_sha, source_locator")

    def _insert(self, table, records):
        # A single vectorized insert avoids one DuckDB statement per uploaded row.
        encoded = canonical(records).decode()
        columns = {**SCHEMAS[table], "source_sha": "VARCHAR", "source_file": "VARCHAR", "source_locator": "VARCHAR"}
        sql_type = "STRUCT(" + ", ".join(f'"{key}" {dtype}' for key, dtype in columns.items()) + ")[]"
        self.db.execute(f"INSERT INTO {table} SELECT item.* FROM unnest(?::JSON::{sql_type}) AS parsed(item)", [encoded])

    def ingest(self, table, filename, raw, *, retain=False, synthetic=False, mapping=None, operator=None, observation="caller"):
        if self.station:
            self.station.require(self.identity, "import")
        filename = re.split(r"[/\\]", filename)[-1]
        digest = sha(raw)
        if not raw or len(raw) > MAX_BYTES:
            raise ValueError("File is empty or exceeds the 32 MiB source limit")
        if digest in self.sources:
            raise ValueError("These exact bytes are already in the case")
        if sum(len(source["raw"]) for source in self.sources.values()) + len(raw) > 256 * 1024 * 1024:
            raise ValueError("Case source bytes exceed the 256 MiB session limit")
        records = []
        issues = []
        missing = Counter()
        structured = table in SCHEMAS and PurePath(filename).suffix.lower() not in ATTACHMENTS
        if not structured and not retain and PurePath(filename).suffix.lower() not in ATTACHMENTS:
            raise ValueError("Select a target evidence table or choose Source archive")
        if structured:
            for locator, row in read_upload(filename, raw):
                if len(records) == MAX_ROWS:
                    raise ValueError("File exceeds the 100,000-row source limit")
                try:
                    record = normalized(table, row, digest, filename, locator, mapping=mapping,
                                        operator=operator, observation=observation)
                    records.append(record)
                    missing.update(key for key in SCHEMAS[table] if record[key] is None)
                except (ValueError, TypeError, InvalidOperation, OverflowError) as error:
                    issues.append(f"{locator}: {error}")
                    if len(issues) == 8:
                        break
            if issues:
                raise ValueError("Validation failed. No rows were imported. " + " | ".join(issues))
            if not records:
                raise ValueError("No data rows found")
            self.db.execute("BEGIN")
            try:
                self._insert(table, records)
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise
        meta = dict(name=filename, table=table if structured else "source_archive", rows=len(records),
                    bytes=len(raw), synthetic=synthetic, missing=dict(missing), mapping=mapping or {},
                    operator=operator, observation=observation if table == "cdr_calls" else None)
        mark = len(self.events)
        previous_review = self.review
        self.sources[digest] = dict(meta, raw=raw)
        self.append_event("source_ingested", dict(meta, sha256=digest))
        self.review = None
        try:
            self.save("import")
        except Exception:
            self.sources.pop(digest)
            self.review = previous_review
            del self.events[mark:]
            if structured:
                self.db.execute(f"DELETE FROM {table} WHERE source_sha=?", [digest])
            raise
        if self.station:
            self.activity("source_imported", record_type=table, rows=len(records), source_sha256=digest)
        self.analysis = None
        return len(records)

    def resolve(self, ip, port, incident, protocol="Any"):
        address = str(ipaddress.IPv4Address(ip.strip()))
        if not str(port).isdigit() or not 1 <= int(port) <= 65535:
            raise ValueError("Enter a port from 1 through 65535")
        instant = as_time(incident)
        window = timedelta(milliseconds=DRIFT_MS)
        rows = self.query("""SELECT * FROM ipdr_cgnat
            WHERE public_ip=? AND ? BETWEEN alloc_port_start AND alloc_port_end
              AND session_start<=? AND session_end>=?
              AND (?='Any' OR protocol=? OR protocol IS NULL)
            ORDER BY session_start, source_sha, source_locator""",
            [address, int(port), instant + window, instant - window, protocol, protocol])
        identities = {(row["telco"], row["caller_msisdn"], row["imsi"], row["imei"]) for row in rows}
        if not rows:
            status = "No candidate"
        elif len(identities) > 1:
            status = "Ambiguous overlap"
        elif not any(rows[0][key] for key in ("caller_msisdn", "imsi")):
            status = "Device candidate only"
        elif not any(row["session_start"] <= instant <= row["session_end"]
                     and (protocol == "Any" or row["protocol"] == protocol) for row in rows):
            status = "Candidate needs clock or protocol corroboration"
        else:
            status = "Unique logged subscriber"
        return status, rows, display_time(instant)


def make_demo():
    case = Case(demo=True)
    people = [
        ("s1", "Rohan Mehta", "+919829077112", "356938035643801|356938035643819", "Shyam Nagar, Jaipur", "DEMO-FIR-014"),
        ("s2", "Aman Verma", "+919876543210", "356938035643819", "Mansarovar, Jaipur", "DEMO-FIR-017"),
        ("s3", "Vikash Sharma", "+919876543211", "356938035643827", "Mansarovar, Jaipur", ""),
        ("s4", "Neha Singh", "+919876543212", "356938035643835", "Shyam Nagar, Jaipur", ""),
        ("s5", "Rajat Kumar", "+919876543213", "356938035643843", "Mansarovar, Jaipur", ""),
    ]
    towers = [("RJ-JPR-MAN-042", "Sector 7 Mansarovar Jaipur", 26.8524, 75.7682, 120),
              ("RJ-JPR-SHY-019", "Shyam Nagar Jaipur", 26.8916, 75.7687, 65),
              ("RJ-JPR-MAL-008", "Malviya Nagar Jaipur", 26.8590, 75.8102, 250)]
    rohan, aman, vikash, neha, rajat = people
    money = [
        ("TXN-88192", f"{DEMO_DATE}T02:20:00+05:30", rohan[1], aman[1], "SBI-***4920", "SBI-***1102", "1820000", "FLAGGED_FRAUD"),
        ("TXN-88193", f"{DEMO_DATE}T02:45:00+05:30", aman[1], vikash[1], "SBI-***1102", "ICICI-***3451", "2430000", "FLAGGED_FRAUD"),
        ("TXN-88194", f"{DEMO_DATE}T02:35:00+05:30", rajat[1], aman[1], "HDFC-***8710", "SBI-***1102", "660000", "SETTLED"),
        ("TXN-88195", f"{DEMO_DATE}T03:12:00+05:30", vikash[1], rajat[1], "ICICI-***3451", "HDFC-***8710", "194000", "SETTLED"),
    ]
    calls = defaultdict(list)
    carriers = ("Jio 5G", "Airtel", "Vi", "BSNL")
    for i, count in enumerate((47, 18, 21, 12, 8)):
        actor = people[i]
        for j in range(count):
            peer_index = (1, 3)[j % 2] if i == 4 else (i + 1 + j % (3 if i == 0 else 2)) % len(people)
            peer = people[peer_index]
            telco = carriers[(i + j // 12) % len(carriers)]
            minute = j
            hour = 2 if j < count - i * 2 else 14
            tower = towers[(j // 15) % 2 if i < 3 else (j // 15 + i) % 3][0]
            imeis = actor[3].split("|")
            calls[telco].append((str(uuid5(NAMESPACE_URL, f"darpan/call/{i}/{j}")), telco,
                                 f"{DEMO_DATE}T{hour:02}:{minute:02}:{(i * 7 + j) % 60:02}+05:30",
                                 actor[2], peer[2], 25 + j * 3, imeis[min(j // 23, len(imeis)-1)],
                                 f"40587000000000{i+1}" if j < 25 or i else "405870000000019", tower,
                                 f"899187000000000000{i+1}" if j < 25 or i else "8991870000000000019", actor[2]))
    ipdr = [
        ("NAT-001", "Jio 5G", f"{DEMO_DATE}T02:18:42.110+05:30", f"{DEMO_DATE}T02:19:04.025+05:30",
         rohan[2], "356938035643801", "405870000000001", "157.34.12.89", 44120, 44000, 44250, "TCP", towers[1][0],
         "8991870000000000001", "Synthetic Messaging", "Messaging", "messaging.example"),
        ("NAT-002", "Airtel", f"{DEMO_DATE}T02:18:41.900+05:30", f"{DEMO_DATE}T02:18:42.006+05:30",
         aman[2], "356938035643819", "405870000000002", "157.34.12.89", 44120, 44000, 44250, "TCP", towers[0][0]),
        ("NAT-003", "Vi", f"{DEMO_DATE}T02:18:41.900+05:30", f"{DEMO_DATE}T02:19:00.000+05:30",
         vikash[2], "356938035643827", "405870000000003", "157.34.12.89", 44310, 44300, 44400, "UDP", towers[0][0]),
    ]
    fixtures = [
        ("suspect_master", "CCTNS_Suspects.csv", people), ("tower_locations", "RJ_UP_Cell_Dump.csv", towers),
        ("bank_ledger", "SBI_Statement.csv", money[:1] + money[2:3]),
        ("bank_ledger", "ICICI_Statement.csv", money[1:2] + money[3:]),
        ("ipdr_cgnat", "Carrier_IPDR.csv", ipdr),
        *(("cdr_calls", f"{carrier.split()[0]}_CDR." + ("tsv" if carrier == "Airtel" else "csv"), rows)
          for carrier, rows in calls.items()),
    ]
    for table, filename, rows in fixtures:
        buf = io.StringIO(newline="")
        if filename.endswith("Airtel_CDR.tsv"):
            writer = csv.writer(buf, delimiter="\t", lineterminator="\n")
            writer.writerow(("Call ID", "Operator", "Call Date", "Call Time", "A-Number", "B-Number",
                             "Billsec", "Handset IMEI", "Subscriber IMSI", "Serving Cell", "SIM ICCID", "Served MSISDN"))
            for record_id, carrier, timestamp, *fields in rows:
                local = as_time(timestamp).astimezone(IST)
                writer.writerow((record_id, carrier, local.strftime("%d/%m/%Y"), local.strftime("%H:%M:%S"), *fields))
        else:
            writer = csv.writer(buf, lineterminator="\n")
            writer.writerow(SCHEMAS[table])
            writer.writerows(rows)
        case.ingest(table, filename, buf.getvalue().encode(), synthetic=True)
    return case

def name_key(value):
    return " ".join(re.findall(r"[\wऀ-ॿ]+", unicodedata.normalize("NFKC", value or "").casefold()))


def analyze(case, *, train_to=None):
    start = time.perf_counter()
    rows = {table: case.all(table) for table in SCHEMAS}
    people = {f"{r['suspect_id']}@{r['source_sha']}:{r['source_locator']}": r for r in rows["suspect_master"]}
    names, phones, evidence, outgoing = (defaultdict(list) for _ in range(4))
    observations = defaultdict(dict)
    account_people, device_people = defaultdict(dict), defaultdict(dict)
    inflow = Counter()
    graph = nx.Graph()
    projection = nx.Graph()
    tower_meta = {r["tower_id"]: r["tower_name"] for r in rows["tower_locations"]}

    def link(a, b, kind, row, other=None):
        citations = [proof(row)]
        if other is not None:
            citations.append(proof(other))
        if graph.has_edge(a, b):
            graph.edges[a, b]["count"] += 1
            graph.edges[a, b]["kind"].add(kind)
            graph.edges[a, b]["proofs"].setdefault(kind, citations)
        else:
            graph.add_edge(a, b, kind={kind}, count=1, proofs={kind: citations})

    def entity(kind, identifier, label=None):
        node = f"{kind}/{identifier}"
        graph.add_node(node, kind=kind, label=label or identifier)
        return node

    def unique(index, key):
        values = index.get(key, ())
        return values[0] if len(values) == 1 else None

    def project(a, b, kind, row, other=None):
        if a and b and a != b:
            link(a, b, kind, row, other)
            projection.add_edge(a, b)
            for node in (a, b):
                if len(evidence[node]) < 12:
                    evidence[node].append(proof(row))
                    if other and len(evidence[node]) < 12:
                        evidence[node].append(proof(other))

    def observe(actor, row, stamp):
        tower = row["cell_tower_id"]
        if tower:
            tower_node = entity("tower", tower, tower_meta.get(tower))
            link(actor, tower_node, "Serving tower", row)
            bucket = int(stamp.timestamp()) // 300
            observations[tower, bucket].setdefault(actor, row)
        if row["imei"]:
            device = entity("device", row["imei"])
            link(actor, device, "Observed IMEI", row)
            device_people[device].setdefault(actor, row)

    for key, r in people.items():
        names[name_key(r["name"])].append(key)
        phones[r["phone"]].append(key)
        graph.add_node(key, kind="person", label=r["name"])
        projection.add_node(key)
        link(key, entity("phone", r["phone"]), "Listed phone", r)
        for imei in r["known_imeis"]:
            device = entity("device", imei)
            link(key, device, "Listed IMEI", r)
            device_people[device].setdefault(key, r)

    for r in rows["cdr_calls"]:
        caller, callee = (unique(phones, r[key]) for key in ("caller_msisdn", "callee_msisdn"))
        observed_party = unique(phones, r["observed_msisdn"] or r["caller_msisdn"])
        if observed_party:
            observe(observed_party, r, r["timestamp"])
        if caller:
            outgoing[caller].append(r)
            if not callee:
                link(caller, entity("phone", r["callee_msisdn"]), "Call", r)
        if callee and not caller:
            link(callee, entity("phone", r["caller_msisdn"]), "Call", r)
        project(caller, callee, "Call", r)

    for r in rows["ipdr_cgnat"]:
        subscriber = unique(phones, r["caller_msisdn"])
        if subscriber:
            observe(subscriber, r, r["session_start"])

    for r in rows["bank_ledger"]:
        sender, receiver = (unique(names, name_key(r[key])) for key in ("sender_name", "receiver_name"))
        origin, target = (entity("account", r[key]) for key in ("sender_acc", "receiver_acc"))
        graph.nodes[target].setdefault("inbound", []).append((r["amount_inr"], proof(r)))
        link(origin, target, "Ledger transfer", r)
        for actor, account in ((sender, origin), (receiver, target)):
            if actor:
                link(actor, account, "Name on ledger", r)
                account_people[account].setdefault(actor, r)
        if receiver:
            inflow[receiver] += r["amount_inr"]
        project(sender, receiver, "Ledger transfer", r)

    shared = Counter()
    observed = Counter()
    for sightings in observations.values():
        observed.update(sightings.keys())
        if len(sightings) > 1:
            shared.update(sightings.keys())
    # Large shared groups are represented by their hub and are never expanded into a clique.
    for kind, groups in (("Shared IMEI", device_people.values()), ("Shared account label", account_people.values()),
                         ("Same sector · 5 min", observations.values())):
        for sightings in groups:
            if not 2 <= len(sightings) <= 25:
                continue
            items = list(sightings.items())
            for i, (actor, first) in enumerate(items):
                for other, second in items[i + 1:]:
                    project(actor, other, kind, first, second)
    for members in phones.values():
        if 2 <= len(members) <= 25:
            for i, actor in enumerate(members):
                for other in members[i + 1:]:
                    project(actor, other, "Shared listed phone", people[actor], people[other])

    stats = {}
    degree = nx.degree_centrality(projection) if len(projection) > 1 else {}
    for key, suspect in people.items():
        calls = sorted(outgoing[key], key=lambda r: (r["timestamp"], r["source_sha"], r["source_locator"]))
        devices = [r["imei"] for r in calls if r["imei"]]
        night = sum(r["timestamp"].astimezone(IST).hour < 6 for r in calls) / max(1, len(calls))
        coloc = shared[key] / max(1, observed[key])
        switches = sum(a != b for a, b in zip(devices, devices[1:]))
        accounts = sum(key in owners and len(owners) > 1 for owners in account_people.values())
        stats[key] = dict(name=suspect["name"], id=suspect["suspect_id"], phone=suspect["phone"],
                          features=(len(calls), night, switches, float(inflow[key]), coloc, degree.get(key, 0.0)),
                          shared_accounts=accounts, observations=observed[key], score=None,
                          citations=list(dict.fromkeys([proof(suspect), *evidence[key]])))
    model = fit_gat(projection, stats, case.demo, train_to=train_to)
    ranking = sorted(stats, key=lambda key: (-(stats[key]["score"] or 0), stats[key]["name"], key))
    result = dict(graph=graph, projection=projection, stats=stats, ranking=ranking,
                  model=model, elapsed=round(time.perf_counter() - start, 3))
    snapshot = inference_snapshot(result)
    case.append_event("analysis_completed", {"sha256": sha(canonical(snapshot)), "model": model["status"]})
    case.analysis = result
    return result


DEMO_LABELS = {"s1": 4, "s2": 3, "s3": 2, "s4": 1, "s5": 0}


def fit_gat(graph, stats, demo, *, train_to=None):
    if not demo:
        return {"status": "Unscored · validated case labels required", "links": [], "epochs": 0}
    nodes = list(graph)
    if len(nodes) != 5 or {stats[node]["id"] for node in nodes} != set(DEMO_LABELS):
        return {"status": "Unscored · fixture labels unavailable", "links": [], "epochs": 0}
    start = time.perf_counter()
    adjacency = torch.tensor(nx.to_numpy_array(graph, nodelist=nodes), dtype=torch.bool)
    attention_mask = adjacency | torch.eye(len(nodes), dtype=torch.bool)
    x = torch.tensor([stats[node]["features"] for node in nodes], dtype=torch.float32)
    x = x / x.abs().amax(dim=0).clamp(min=1)
    labels = torch.tensor([DEMO_LABELS[stats[node]["id"]] for node in nodes])
    pairs = torch.triu_indices(len(nodes), len(nodes), offset=1)
    model = None if train_to is not None else models.graph_from_checkpoint(x, adjacency, labels)
    loaded = model is not None
    if model is None:
        model = models.train_graph(x, adjacency, labels)
    if train_to is not None:
        models.write_checkpoint(train_to, model, x, adjacency, labels)
    with torch.no_grad():
        classes, links = model(x, attention_mask)
        bands = torch.tensor([0.50, 0.62, 0.75, 0.87, 0.99])
        scores = classes.softmax(dim=1) @ bands
        for node, score in zip(nodes, scores.tolist()):
            stats[node]["score"] = round(score * 100, 2)
        candidates = []
        for i, j in zip(pairs[0].tolist(), pairs[1].tolist()):
            if not adjacency[i, j] and nx.has_path(graph, nodes[i], nodes[j]):
                path = nx.shortest_path(graph, nodes[i], nodes[j])
                candidates.append(dict(a=stats[nodes[i]]["name"], b=stats[nodes[j]]["name"],
                                       hops=len(path) - 1, score=round(links[i, j].sigmoid().item(), 4)))
        candidates.sort(key=lambda candidate: -candidate["score"])
    return dict(status="Synthetic training fit", epochs=models.GRAPH_EPOCHS,
                seconds=round(time.perf_counter() - start, 3),
                weights_sha256=models.digest(models.weight_values(model)), band_values=bands.tolist(),
                labels=DEMO_LABELS, links=candidates,
                origin="Local checkpoint" if loaded else "Trained locally from scratch")


def inference_snapshot(analysis):
    return {"model": analysis["model"], "features": FEATURE_NAMES,
            "ranking": [analysis["stats"][key] for key in analysis["ranking"]]}


@st.cache_resource(show_spinner=False)
def intent_parser():
    return models.load_intent()


def bank_trail(case, name, limit=100):
    same_name = case.query("SELECT name FROM suspect_master WHERE lower(name)=lower(?) LIMIT 2", [name])
    if len(same_name) > 1:
        raise ValueError("Multiple profiles have this name. Resolve the identity before querying the ledger.")
    # Follow account labels only after the initiating transfer and only for one additional hop.
    return case.query("""WITH first_hop AS (
        SELECT * FROM bank_ledger WHERE lower(sender_name)=lower(?)
    ), trail AS (
        SELECT 1 AS hop, * FROM first_hop
        UNION ALL
        SELECT 2 AS hop, b.* FROM bank_ledger b
        WHERE lower(b.sender_name)<>lower(?) AND EXISTS (
            SELECT 1 FROM first_hop a
            WHERE a.receiver_acc=b.sender_acc AND lower(a.receiver_name)=lower(b.sender_name)
              AND b.timestamp >= a.timestamp
        )
    ) SELECT * FROM trail ORDER BY hop, timestamp, source_sha, source_locator LIMIT ?""", [name, name, limit])


def tower_calls(case, tower, start, end, limit=100):
    if end <= start:
        raise ValueError("End time must be after start time")
    return case.query("""SELECT * FROM cdr_calls WHERE cell_tower_id=? AND timestamp>=? AND timestamp<?
        ORDER BY timestamp, source_sha, source_locator LIMIT ?""", [tower, start, end, limit])


def classify_question(question):
    vocab, net = intent_parser()
    x = torch.tensor(models.vector(question, vocab))
    with torch.no_grad():
        confidence, index = net(x).softmax(dim=0).max(dim=0)
    return models.INTENTS[index.item()] if x.sum() > 0 and confidence.item() >= 0.66 else "other"


def resolve_question(case, question):
    hindi = bool(re.search(r"[\u0900-\u097f]", question))
    intent = classify_question(question)
    text = name_key(question)
    if intent == "bank" and re.search(r"\b(?:bank|transfer|payment|ledger|transactions?)\b|money trail|बैंक|लेनदेन", text):
        names = {r["name"] for r in case.all("suspect_master")}
        if case.demo:
            translations = {"रोहन मेहता": "rohan mehta", "अमन वर्मा": "aman verma",
                            "विकाश शर्मा": "vikash sharma", "विकास शर्मा": "vikash sharma",
                            "नेहा सिंह": "neha singh", "रजत कुमार": "rajat kumar"}
            for local, english in translations.items():
                if f" {local} " in f" {text} ":
                    text += " " + english
        matches = [name for name in sorted(names) if f" {name_key(name)} " in f" {text} "]
        if len(matches) == 1:
            return ("धन का लेनदेन" if hindi else "Bank trail"), bank_trail(case, matches[0], 101), "bank"
        return ("कृपया एक पूरा संदिग्ध नाम दें।" if hindi else "Enter one full suspect name as listed in the case."), [], "bank"
    if intent == "tower" and re.search(r"\btower\b|टावर", text):
        named = {}
        for row in case.all("tower_locations"):
            tower_id = row["tower_id"]
            if name_key(tower_id) in text or name_key(row["tower_name"]) in text:
                named[tower_id] = row
            elif case.demo and (("mansarovar" in text or "मानसरोवर" in text) and "MAN-042" in tower_id
                                or ("sector 62" in text or "सेक्टर 62" in text) and "S62" in tower_id):
                named[tower_id] = row
        if len(named) != 1:
            return ("कृपया एक टावर आईडी दें।" if hindi else "Enter one tower ID or exact site name."), [], "tower"
        incident_date = re.search(r"\b\d{4}-\d{2}-\d{2}\b", question)
        clocks = re.findall(r"\b\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?\b", question)
        if not clocks and case.demo:
            clocks = ["02:00", "04:00"]
        date = incident_date.group() if incident_date else DEMO_DATE if case.demo else None
        if not date or len(clocks) != 2:
            return ("तारीख और IST समय-सीमा दें।" if hindi else "Enter an ISO date and two IST times, e.g. 2026-01-14 02:00 to 04:00."), [], "tower"
        start, end = (as_time(f"{date}T{clock}+05:30") for clock in clocks)
        rows = tower_calls(case, next(iter(named)), start, end, 101)
        heading = "टावर कॉल" if hindi else "Tower calls"
        return f"{heading} · {next(iter(named))} · {date} {clocks[0]}–{clocks[1]} IST", rows, "tower"
    return ("टावर कॉल या बैंक लेनदेन के बारे में पूछें।" if hindi else
            "Ask about tower calls or a named person's bank trail."), [], "other"


def snapshot(case, analysis):
    files = {f"normalized/{table}.json": canonical(case.all(table)) for table in SCHEMAS}
    files["analysis/inference.json"] = canonical(inference_snapshot(analysis))
    for digest, source in case.sources.items():
        safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", source["name"]).strip(".") or "source"
        files[f"raw/{digest}/{safe_name}"] = source["raw"]
    content_hashes = {path: sha(data) for path, data in sorted(files.items())}
    events = list(case.events)
    event = dict(index=len(events) + 1, at=datetime.now(UTC), action="snapshot_prepared",
                 payload=content_hashes, previous=events[-1]["hash"])
    events.append(dict(event, hash=sha(canonical(event))))
    files["custody/events.json"] = canonical(events)
    return files, events[-1]["hash"]


def certificate(case, analysis):
    files, head = snapshot(case, analysis)
    checksums = {path: sha(data) for path, data in sorted(files.items())}
    hash_table = "".join(f"<tr><td>{esc(path)}</td><td><code>{digest}</code></td></tr>"
                         for path, digest in checksums.items())
    fields = (
        "Name, designation and contact details", "Case number and record(s) tendered",
        "Device or record source, make, model, serial and applicable identifiers",
        "Acquisition method, date, time and production process",
        "Lawful control, regular use, ordinary-course input and operating conditions",
        "Exceptions or interruptions and effect on the record",
        "Name, signature, date, time (IST) and place",
    )
    def blanks(items):
        return "".join(f"<p><b>{esc(item)}</b><br><span class='line'></span></p>" for item in items)
    mode = "SYNTHETIC DEMONSTRATION" if case.demo else "LOCAL CASE EXPORT"
    document = f"""<!doctype html><html lang="en"><meta charset="utf-8"><title>DARPAN Evidence Export</title>
<style>body{{max-width:960px;margin:42px auto;padding:24px;font:15px/1.55 Georgia;color:#102035}}
h1,h2{{line-height:1.15}}.notice{{background:#fff1d7;padding:12px}}code{{overflow-wrap:anywhere}}
td,th{{border-bottom:1px solid #ccc;text-align:left;padding:7px;overflow-wrap:anywhere}}
table{{border-collapse:collapse;width:100%;table-layout:fixed}}.line{{display:block;border-bottom:1px dotted #777;height:24px}}
@media print{{body{{margin:0;padding:0}}td,tr{{break-inside:avoid}}}}</style>
<h1>Electronic evidence and hash report</h1><p>{mode} · DARPAN FORENSICS {VERSION}</p>
<p class="notice">Unsigned preparation worksheet for the party and expert. Complete the prescribed Schedule certificate with verified record particulars and signatures before submission.</p>
<p>Reference <a href="{BSA}">Bharatiya Sakshya Adhiniyam, 2023, Section 63 and Schedule</a></p>
<h2>Part A · Party</h2>{blanks(fields)}
<h2>Part B · Expert</h2>{blanks(("Name, designation and contact details", "Record source and identifying particulars",
"Tools, process and verification performed", "Verified SHA-256 values and attached hash report",
"Name, signature, date, time (IST) and place"))}
<h2>SHA-256 annexure</h2><p>Custody chain head <code>{head}</code></p>
<p>The companion ZIP contains the exact hashed bytes. The custody chain is independently checkable against a separately retained head.</p>
<table><thead><tr><th>Archive member</th><th>SHA-256</th></tr></thead><tbody>{hash_table}</tbody></table></html>"""
    return document, files, checksums, head


def evidence_zip(document, files, checksums, head):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, contents in files.items():
            archive.writestr(path, contents)
        archive.writestr("section-63-worksheet.html", document)
        archive.writestr("manifest.json", canonical({"chain_head": head, "files": checksums,
                                                       "worksheet_sha256": sha(document.encode())}))
    return output.getvalue()



FINGERPRINT = """<svg viewBox="0 0 32 32" width="33" height="33" fill="none" aria-hidden="true"
stroke="#e5bb7a" stroke-width="1.45" stroke-linecap="round" xmlns="http://www.w3.org/2000/svg"><path d="M5 13a11 11 0 0 1 22 0m-24 6v-3m26 0v3m-7 8a21 21 0 0 0 3-12 9 9 0 0 0-18 0c0 4-.4 6-1 8m3 3c1-2 2-5 2-10a5 5 0 1 1 10 0c0 6-1 10-4 13m-5 0c2-3 4-6 4-13m11 8c1-2 1-4 1-6"/></svg>"""
FINGERPRINT_URI = "data:image/svg+xml;base64," + base64.b64encode(FINGERPRINT.encode()).decode()
CSS = """
<style>
:root{--paper:#161715;--surface:#1e201c;--surface-raised:#262923;--line:#3a3d35;
--ink:#f3f1e8;--muted:#b7b9ac;--accent:#e5bb7a;--accent-ink:#211b12;
--mono:"Cascadia Mono",Consolas,monospace;--sans:"Segoe UI",system-ui,sans-serif;--serif:Georgia,serif}
.stApp,[data-testid="stAppViewContainer"]{background:var(--paper);color:var(--ink);font-family:var(--sans)}
[data-testid="stHeader"],[data-testid="stToolbar"]{display:none!important}
[data-testid="stMainBlockContainer"]{max-width:1560px;padding:0 clamp(16px,3vw,44px) 32px}
[data-testid="stVerticalBlock"]{gap:12px}
[data-testid="stHorizontalBlock"]{gap:16px}
[data-testid="stMarkdownContainer"],[data-testid="stWidgetLabel"] p{color:var(--ink)}
[data-testid="stWidgetLabel"] p{font-size:.83rem;font-weight:600}
[data-testid="stCaptionContainer"] p{color:var(--muted);font-size:.83rem;line-height:1.5}
.st-key-case_controls{padding:8px 0;border-bottom:1px solid var(--line)}
.st-key-case_controls [data-testid="stHorizontalBlock"]{align-items:center}
.st-key-workspace [data-testid="stHorizontalBlock"]{align-items:start}
.st-key-rail{border-left:1px solid var(--line);padding-left:19px}
:is(.st-key-lookup_form,.st-key-search_form){background:var(--surface);border:1px solid var(--line);border-radius:7px;padding:18px}
.st-key-resolver,.st-key-copilot,.st-key-sources{max-width:1120px;padding:12px 0 4px}
.st-key-source_summary{padding-top:15px;border-top:1px solid var(--line)}
[data-testid="stForm"]{padding:0;border:0}
[data-testid="stHeadingWithActionElements"] h2{font-size:1.4rem}
[data-testid="stTabs"] [role="tablist"]{gap:20px;border-bottom:1px solid var(--line)}
[data-testid="stTabs"] [role="tab"]{min-height:42px;padding:0 4px;color:var(--muted);border-bottom:2px solid transparent}
[data-testid="stTabs"] [role="tab"][aria-selected="true"]{color:var(--accent);font-weight:650;border-bottom-color:var(--accent)}
[data-testid="stTabs"] [role="tab"]:hover{color:var(--ink)}
[data-testid="stTabs"] [role="tab"] p{color:inherit}
[data-testid="stTabs"] [role="tablist"]::after{display:none}
[data-testid="stTabs"] [role="tabpanel"]{padding-top:12px}
[data-testid="stTextInput"] [data-baseweb="input"],[data-testid="stTextInput"] input,
[data-testid="stSelectbox"] [data-testid="stSelectboxVirtualDropdown"],
[data-testid="stSelectbox"] [role="combobox"]{background:var(--surface)!important;color:var(--ink)!important}
.stButton button,.stFormSubmitButton button,.stDownloadButton button{
  color:var(--ink)!important;background:var(--surface)!important;border:1px solid #54594d!important;
  border-radius:6px;min-height:42px;font-size:.84rem;font-weight:620}
.stButton button:hover,.stFormSubmitButton button:hover,.stDownloadButton button:hover{border-color:var(--accent)!important;background:var(--surface-raised)!important}
.stButton button:active,.stFormSubmitButton button:active,.stDownloadButton button:active{transform:translateY(1px)}
.stButton button:disabled,.stFormSubmitButton button:disabled,.stDownloadButton button:disabled{opacity:.54;transform:none}
.stApp button:is([data-testid="stBaseButton-primary"],[data-testid="stBaseButton-primaryFormSubmit"]){
  color:var(--accent-ink)!important;background:var(--accent)!important;border-color:var(--accent)!important}
[data-testid="stBaseButton-primary"] p,[data-testid="stBaseButton-primaryFormSubmit"] p{color:var(--accent-ink)!important}
.stApp button:is([data-testid="stBaseButton-primary"],[data-testid="stBaseButton-primaryFormSubmit"]):hover{background:#f1cf97!important}
.stApp :is(button,input,summary,[role="combobox"],[tabindex="0"]):focus-visible{outline:2px solid var(--accent);outline-offset:2px}
[data-testid="stDialog"] [role="dialog"]{background:var(--surface);color:var(--ink);border:1px solid var(--line)}
[data-testid="stExpander"] details{border-color:var(--line);border-radius:6px}
.masthead{display:flex;align-items:center;justify-content:space-between;gap:14px;min-height:46px;border-bottom:1px solid var(--line)}
.wordmark{display:flex;align-items:center;gap:9px;font-size:.93rem;font-weight:700;color:var(--ink)}
.wordmark img{display:block;width:23px;height:23px}
.station-meta,.eyebrow,.footer{color:var(--muted);font:.74rem/1.5 var(--mono)}
.station-meta{text-align:right}
.case-title{margin:3px 0 1px;font:400 clamp(1.85rem,3vw,2.85rem)/1.04 var(--serif);letter-spacing:-.035em}
.eyebrow{color:var(--accent)}
.section{font:650 1.05rem/1.25 var(--sans);letter-spacing:-.018em;margin:0 0 4px;color:var(--ink)}
.view-title{font:400 1.72rem/1.15 var(--serif);letter-spacing:-.022em;margin:0 0 5px}
.section-detail{color:var(--muted);font:.83rem/1.5 var(--sans);margin:0}
.table-wrap{overflow-x:auto}
.ledger{border-collapse:collapse;width:100%;font:.84rem/1.35 var(--sans);text-align:left}
.ledger :is(th,td){padding:9px 4px;border-bottom:1px solid var(--line);vertical-align:top}
.ledger th{color:var(--muted);font-size:.75rem;font-weight:600}
.ledger td{overflow-wrap:anywhere}
.ledger .num{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}
.ledger .score{color:var(--accent);font-weight:650}
.ledger .row-meta{display:block;margin-top:2px;font-size:.75rem;color:var(--muted)}
.ledger .digest{font:.75rem var(--mono);white-space:nowrap}
.st-key-source_index .ledger :is(th,td){padding:11px 12px}
.st-key-source_index .ledger th{background:var(--surface);color:var(--ink)}
.st-key-network_title [data-testid="stHorizontalBlock"]{align-items:center}
.st-key-network_title .view-title{margin:0}
.footer{display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-top:10px;padding-top:10px;border-top:1px solid var(--line)}
@media(max-width:980px){
  .st-key-workspace [data-testid="stHorizontalBlock"]:has(.st-key-rail){flex-wrap:wrap}
  .st-key-workspace [data-testid="stHorizontalBlock"]:has(.st-key-rail)>[data-testid="stColumn"]{flex:1 1 100%!important;width:100%!important}
  .st-key-rail{border-left:0;border-top:1px solid var(--line);padding:16px 0 0}
}
@media(max-width:700px){
  [data-testid="stHorizontalBlock"]{flex-wrap:wrap}
  [data-testid="stHorizontalBlock"]>[data-testid="stColumn"]{flex:1 1 100%!important;width:100%!important}
  [data-testid="stTabs"] [role="tablist"]{gap:7px}
  [data-testid="stTabs"] [role="tablist"]{flex-wrap:wrap}
  [data-testid="stTabs"] [role="tab"] p{font-size:.83rem;white-space:nowrap}
  .st-key-case_controls [data-testid="stHorizontalBlock"]{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:9px}
  .st-key-case_controls [data-testid="stHorizontalBlock"]>[data-testid="stColumn"]:first-child{grid-column:1/-1}
  .st-key-case_controls [data-testid="stHorizontalBlock"]>[data-testid="stColumn"]{min-width:0!important}
  .st-key-network_title [data-testid="stHorizontalBlock"]{flex-wrap:nowrap}
  .st-key-network_title [data-testid="stHorizontalBlock"]>[data-testid="stColumn"]{min-width:0!important;flex:1 1 0!important;width:auto!important}
  .st-key-network_title [data-testid="stHorizontalBlock"]>[data-testid="stColumn"]:last-child{flex:0 0 112px!important}
  .st-key-network_title .view-title{font-size:clamp(1.3rem,5vw,1.72rem)}
  .station-meta{font-size:.65rem}
  :is(.st-key-lookup_form,.st-key-search_form){padding:12px}
}
@media(prefers-reduced-motion:reduce){.stApp *{transition:none!important;scroll-behavior:auto!important}}
</style>
"""


def section(title, detail=None, *, page=False):
    heading = "view-title" if page else "section"
    level = "h2" if page else "h3"
    extra = f'<p class="section-detail">{esc(detail)}</p>' if detail else ""
    st.html(f'<{level} class="{heading}">{esc(title)}</{level}>' + extra)



GRAPH_CSS = """
:root{color-scheme:dark;--text:#deedf0;--muted:#91aeb4;--teal:#78e6dc;
--line:#234047;--sans:"Segoe UI",system-ui,sans-serif;--mono:"Cascadia Mono",Consolas,monospace}
*{box-sizing:border-box}html,body{margin:0;overflow:hidden}
.stage{border:1px solid var(--line);border-radius:10px;overflow:hidden;background:#071218;color:var(--text);font:1rem var(--sans)}
.instrument{display:flex;align-items:end;justify-content:space-between;flex-wrap:wrap;gap:12px;padding:10px 14px;
background:#0d1d23;border-bottom:1px solid var(--line)}
.entity-field{display:grid;gap:4px;min-width:0;flex:1 1 12rem;max-width:21rem}
.entity-field label{font-size:.8125rem;color:#b9ced3}
.controls,.zoom-group{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.controls button,.entity-field select{background:#12272e;color:#deedf0;border:1px solid #526c72;border-radius:7px;
min-height:44px;min-width:44px;padding:5px 10px;font:600 .875rem var(--sans);cursor:pointer}
.entity-field select{width:100%;font-weight:500}
.zoom-level{padding:0 6px;color:#b9ced3;font-size:.8125rem;font-variant-numeric:tabular-nums}
.controls button:hover{background:#1c3840;color:#fff}
.controls button[aria-disabled="true"]{opacity:.55;cursor:default}
.controls button:focus-visible,.entity-field select:focus-visible,.canvas-scroll:focus-visible,.inspector-details:focus-visible{
  outline:2px solid #9bf8ec;outline-offset:-3px}
.sr-only{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%);white-space:nowrap}
.canvas-scroll{overflow:auto}
svg{display:block;width:100%;height:auto;min-height:390px;max-height:635px;cursor:default;touch-action:pan-y}
.stage.pan-active svg{cursor:grab;touch-action:none}
.stage.dragging svg{cursor:grabbing}
.ambient{transform-origin:500px 270px;animation:scan 28s linear infinite;pointer-events:none}
@keyframes scan{to{transform:rotate(360deg)}}
.echo{transform-box:fill-box;transform-origin:center;animation:echo 3.8s ease-out infinite;pointer-events:none}
@keyframes echo{0%,18%{opacity:.48;transform:scale(.76)}85%,100%{opacity:0;transform:scale(1.5)}}
.wire path{transition:opacity 180ms,stroke-width 180ms}
.wire .base{opacity:.46}.wire .signal{opacity:0;stroke-dasharray:3 14}
.wire.is-selected .base{opacity:.82;stroke-width:2}
.wire.is-selected .signal{opacity:.8;animation:trace 2.2s linear infinite}
.wire.is-dim .base{opacity:.14}
@keyframes trace{to{stroke-dashoffset:-34}}
.map-node{cursor:pointer;outline:none}.map-node .node-ring{transition:stroke-width 160ms,fill 160ms}
.map-node .hit-area{fill:transparent;pointer-events:all}
.map-node .keyboard-ring{visibility:hidden;vector-effect:non-scaling-stroke}
.map-node:focus-visible .keyboard-ring{visibility:visible}
.map-node:hover .node-ring,.map-node:focus-visible .node-ring,.map-node[aria-pressed="true"] .node-ring{
stroke:#e8ffff;stroke-width:2.4;fill:#16343b}
.map-node text{pointer-events:none;paint-order:stroke;stroke:#071218;stroke-width:4px;stroke-linejoin:round}
.map-node .echo{display:none}.map-node[aria-pressed="true"] .echo{display:block}
.radar{vector-effect:non-scaling-stroke}
.inspector{display:grid;grid-template-columns:minmax(9rem,.72fr) minmax(0,2fr);gap:14px;padding:14px;
min-height:86px;border-top:1px solid var(--line);background:#0b1a20}
.inspector h3{font-size:1rem;margin:3px 0;overflow-wrap:anywhere}
.inspector .type{font-size:.8125rem;color:var(--teal)}
.inspector-details{max-height:12rem;overflow:auto;font-size:.875rem;color:#c7dbdf;line-height:1.4}
.inspector-details div{overflow-wrap:anywhere;padding:5px 8px 7px 4px}
.inspector-details div+div{border-top:1px solid var(--line)}
.inspector-details small{display:block;color:#9bb3b8;font:.8125rem/1.5 var(--mono);overflow-wrap:anywhere}
.paused *{animation-play-state:paused!important}
@media(max-width:620px){
  svg{min-width:610px;min-height:335px}.inspector{grid-template-columns:1fr;gap:6px}
}
@media(prefers-reduced-motion:reduce){
  .stage:not(.allow-motion) *{animation:none!important;transition:none!important}
  .stage:not(.allow-motion) .echo{opacity:.28}
}
"""


def draw_topology(graph, nodes, focus, stats):
    colors = {"person": "#83badd", "account": "#7cddaf", "tower": "#7fe1e0",
              "phone": "#b4b4e8", "device": "#edbe85"}
    kinds = {"person": "Person", "account": "Account", "tower": "Serving tower",
             "phone": "Phone", "device": "Device"}
    indexes = {node: i for i, node in enumerate(nodes)}
    reduced = graph.subgraph(nodes)
    positions = {focus: (500, 270)}
    peers = [node for node in nodes if node != focus]
    for i, node in enumerate(peers):
        angle = -math.pi * .68 + math.tau * i / len(peers)
        positions[node] = (500 + 354 * math.cos(angle), 270 + 179 * math.sin(angle))
    wires = []
    for a, b, meta in reduced.edges(data=True):
        x1, y1 = positions[a]
        x2, y2 = positions[b]
        kind = graph.nodes[b]["kind"] if graph.nodes[b]["kind"] != "person" else graph.nodes[a]["kind"]
        color = "#76d6d3" if focus in (a, b) and kind == "person" else colors[kind]
        width = min(2.15, 1 + math.log1p(meta["count"]) * .29)
        path = f"M{x1:.1f},{y1:.1f} Q{(x1+x2)*.5 + (y2-y1)*.11:.1f},{(y1+y2)*.5 - (x2-x1)*.11:.1f} {x2:.1f},{y2:.1f}"
        wires.append(f'<g class="wire" data-a="{indexes[a]}" data-b="{indexes[b]}" fill="none">'
                     f'<path class="base" d="{path}" stroke="{color}" stroke-width="{width:.2f}"/>'
                     f'<path class="signal" d="{path}" stroke="{color}" stroke-width="3"/>'
                     f'<title>{esc(", ".join(sorted(meta["kind"])))}</title></g>')
    markers, details = [], []
    for node in nodes:
        x, y = positions[node]
        meta = graph.nodes[node]
        kind = meta["kind"]
        active = node == focus
        color = "#8ef1e6" if active else colors[kind]
        radius = 33 if active else 18
        label = meta["label"]
        short = label if len(label) <= 27 else label[:25] + "…"
        caption = ("Focus number" if kind == "phone" else "Focus person") if active else kinds[kind]
        if node in stats and stats[node]["score"] is not None and active:
            caption += f' · {stats[node]["score"]:.1f}% demo score'
        marker = {
            "person": '<circle r="5" fill="currentColor"/>',
            "account": '<path d="M-7,-2 L0,-6 L7,-2 M-6,-1 H6 M-5,1 V5 M0,1 V5 M5,1 V5 M-7,6 H7"/>',
            "tower": '<path d="M0,-6 L-5,7 M0,-6 L5,7 M-3,3 H3 M-6,-7 Q-9,-3 -6,0 M6,-7 Q9,-3 6,0"/>',
            "phone": '<rect x="-4" y="-7" width="8" height="14" rx="1"/>',
            "device": '<rect x="-5" y="-5" width="10" height="10" rx="1"/><path d="M-8,-2H-5 M-8,2H-5 M5,-2H8 M5,2H8"/>',
        }[kind]
        markers.append(
            f'<g class="map-node" role="button" tabindex="0" aria-label="{esc(label)}" aria-pressed="false" '
            f'data-index="{indexes[node]}" transform="translate({x:.1f} {y:.1f})">'
            f'<title>{esc(label)}</title><circle r="{radius + 13}" fill="url(#node-glow)" opacity=".46"/>'
            f'<circle class="hit-area" r="36"/><circle class="keyboard-ring" r="{radius+9}" fill="none" '
            f'stroke="#9bf8ec" stroke-width="2"/>'
            f'<circle class="echo" r="{radius+7}" fill="none" stroke="{color}" stroke-width="1.4"/>'
            f'<circle r="{radius + 5}" fill="none" stroke="{color}" stroke-dasharray="2 6" opacity=".40"/>'
            f'<circle class="node-ring" r="{radius}" fill="#0c2229" stroke="{color}" stroke-width="1.5"/>'
            f'<g color="{color}" fill="none" stroke="currentColor" stroke-linecap="round" stroke-width="1.4"> '
            f'{marker}</g><text y="{radius+18}" text-anchor="middle" fill="#e6f4f6" font-size="{19 if active else 16}" '
            f'font-weight="650" font-family="Segoe UI,system-ui">{esc(short)}</text>'
            f'<text y="{radius+34}" text-anchor="middle" fill="{color}" font-size="11" '
            f'font-family="Consolas,monospace">{esc(caption)}</text></g>')
        entries = []
        inbound = meta.get("inbound")
        if inbound:
            amount, source = max(inbound, key=lambda item: item[0])
            entries.append((f"Largest inbound transfer · {money_text(amount)}", [source]))
        if node in stats:
            entries.append(("Suspect profile", stats[node]["citations"][:1]))
        for peer, relationship in sorted(reduced[node].items(), key=lambda item: -item[1]["count"]):
            for relation, proofs in sorted(relationship["proofs"].items()):
                entries.append((f"{graph.nodes[peer]['label']} · {relation}", proofs))
        entry_html = "".join(f'<div>{esc(title)}<small>{esc(" & ".join(proofs))}</small></div>'
                             for title, proofs in entries)
        details.append(f'<template data-evidence="{indexes[node]}"><div><div class="type">{kinds[kind]}</div>'
                       f'<h3>{esc(label)}</h3></div><div class="inspector-details" tabindex="0" aria-label="Source rows">'
                       f'{entry_html or "No linked source rows in this view."}</div></template>')
    return "".join(wires), "".join(markers), "".join(details), indexes[focus]


def graph_view(analysis, focus, layer):
    graph = analysis["graph"]
    if layer == "Calls":
        nodes = [focus, *sorted(graph[focus], key=lambda node: (-graph[focus][node]["count"], node))[:9]]
    elif layer == "Overview":
        nearby_people = sorted((node for node in graph[focus] if graph.nodes[node]["kind"] == "person"),
                               key=lambda node: (-graph[focus][node]["count"], graph.nodes[node]["label"]))[:4]
        nodes = [focus, *nearby_people]
        for kind, limit in (("account", 3), ("tower", 1), ("device", 1)):
            options = {peer for node in (focus, *nearby_people) for peer in graph[node]
                       if graph.nodes[peer]["kind"] == kind}
            nodes.extend(sorted(options, key=lambda node: (-graph.degree(node), node))[:limit])
    else:
        kinds = {"Accounts": {"account"}, "Devices & phones": {"device", "phone"},
                 "Tower observations": {"tower"}}[layer]
        options = [node for node in graph[focus] if graph.nodes[node]["kind"] in kinds][:6]
        linked = {peer for node in options for peer in graph[node] if peer != focus
                  and graph.nodes[peer]["kind"] == "person"}
        nodes = [focus, *options, *sorted(linked, key=lambda node: graph.nodes[node]["label"])[:3]]
    nodes = list(dict.fromkeys(nodes))
    wires, markers, details, selected = draw_topology(graph, nodes, focus, analysis["stats"])
    options = "".join(f'<option value="{index}">{esc(graph.nodes[node]["label"])}</option>'
                      for index, node in enumerate(nodes))
    view = f"""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Network map</title>
<style>{GRAPH_CSS}</style>
<div class="stage">
<div class="instrument">
<div class="entity-field"><label for="entity">Inspect entity</label><select id="entity">{options}</select></div>
<div class="controls" role="group" aria-label="Map controls">
<div class="zoom-group" role="group" aria-label="Map zoom">
<button data-action="out" aria-label="Zoom out">−</button>
<span class="zoom-level" aria-live="polite" aria-label="Zoom level">100%</span>
<button data-action="in" aria-label="Zoom in">+</button>
<button data-action="reset">Fit map</button></div>
<button data-action="motion">Pause motion</button></div></div>
<p class="sr-only" id="pan-help">When zoomed in, use the arrow keys to pan the map.</p>
<div class="canvas-scroll" tabindex="0" role="region" aria-label="Network canvas" aria-describedby="pan-help">
<svg viewBox="0 0 1000 540" role="group" aria-label="Interactive evidence map">
<defs>
<pattern id="dots" width="20" height="20" patternUnits="userSpaceOnUse"><circle cx="1" cy="1" r=".85" fill="#36535c" opacity=".55"/></pattern>
<radialGradient id="field"><stop stop-color="#172832"/><stop offset=".72" stop-color="#101b22"/><stop offset="1" stop-color="#0d151a"/></radialGradient>
<radialGradient id="node-glow"><stop stop-color="#6eeded" stop-opacity=".34"/><stop offset="1" stop-color="#4ddede" stop-opacity="0"/></radialGradient>
<linearGradient id="sweep" x1="0" x2="1" y1="0" y2="1"><stop stop-color="#42dcc7" stop-opacity="0"/><stop offset="1" stop-color="#42dcc7" stop-opacity=".14"/></linearGradient>
</defs>
<rect width="100%" height="100%" fill="url(#field)"/><rect width="100%" height="100%" fill="url(#dots)"/>
<g class="world">
<g class="radar" fill="none" pointer-events="none" stroke="#2e777d">
<ellipse cx="500" cy="270" rx="354" ry="179" opacity=".55"/>
<ellipse cx="500" cy="270" rx="286" ry="145" stroke-dasharray="2 7" opacity=".6"/>
<ellipse cx="500" cy="270" rx="212" ry="107" opacity=".38"/>
<ellipse cx="500" cy="270" rx="119" ry="60" opacity=".56"/>
<path d="M95 270H905 M500 49V491" stroke-dasharray="4 9" opacity=".30"/>
</g>
<g class="ambient"><path d="M500 270L879 111Q905 210 892 270Z" fill="url(#sweep)"/>
<path d="M566 270H892" stroke="#70e7da" stroke-opacity=".28"/></g>
{wires}{markers}</g></svg></div>
<div class="inspector" role="region" aria-label="Selected entity evidence"></div>
<div class="sr-only selection-status" role="status"></div>{details}
</div>
<script>
const stage = document.querySelector('.stage');
const canvas = stage.querySelector('svg');
const world = canvas.querySelector('.world');
const nodes = [...canvas.querySelectorAll('.map-node')];
const wires = [...canvas.querySelectorAll('.wire')];
const inspector = stage.querySelector('.inspector');
const picker = stage.querySelector('#entity');
const viewport = stage.querySelector('.canvas-scroll');
const selectionStatus = stage.querySelector('.selection-status');
const reduced = matchMedia('(prefers-reduced-motion: reduce)');
const motionButton = stage.querySelector('[data-action=motion]');
let manualMotion = null;
let zoom = 1, x = 0, y = 0, drag = null;
const motionKey = 'darpan-network-motion';
try {{
  const saved = sessionStorage.getItem(motionKey);
  if (saved === 'on' || saved === 'off') manualMotion = saved === 'on';
}} catch {{ /* The frame may run with storage disabled. */ }}
function syncMotion() {{
  const playing = manualMotion ?? !reduced.matches;
  stage.classList.toggle('paused', !playing);
  stage.classList.toggle('allow-motion', manualMotion === true);
  motionButton.textContent = playing ? 'Pause motion' : 'Play motion';
}}
const paint = () => {{
  world.setAttribute('transform', 'translate(' + x + ' ' + y + ') translate(500 270) scale(' + zoom + ') translate(-500 -270)');
  stage.classList.toggle('pan-active', zoom > 1);
  stage.querySelector('[data-action=out]').setAttribute('aria-disabled', String(zoom <= 1));
  stage.querySelector('[data-action=in]').setAttribute('aria-disabled', String(zoom >= 2));
  stage.querySelector('.zoom-level').textContent = Math.round(zoom * 100) + '%';
}};
function select(node) {{
  const id = node.dataset.index;
  for (const item of nodes) item.setAttribute('aria-pressed', String(item === node));
  for (const edge of wires) {{
    const incident = edge.dataset.a === id || edge.dataset.b === id;
    edge.classList.toggle('is-selected', incident);
    edge.classList.toggle('is-dim', !incident);
  }}
  inspector.replaceChildren(stage.querySelector('[data-evidence="' + id + '"]').content.cloneNode(true));
  picker.value = id;
  selectionStatus.textContent = node.getAttribute('aria-label') + ' selected. Source rows updated.';
}}
picker.addEventListener('change', () => select(nodes[Number(picker.value)]));
for (const node of nodes) {{
  node.addEventListener('click', () => select(node));
  node.addEventListener('keydown', event => {{
    if (event.key === 'Enter' || event.key === ' ') {{ event.preventDefault(); select(node); }}
  }});
}}
function setZoom(value) {{
  zoom = Math.min(2, Math.max(1, value));
  pan(x, y);
}}
function pan(nextX, nextY) {{
  const limitX = 500 * (zoom - 1), limitY = 270 * (zoom - 1);
  x = Math.max(-limitX, Math.min(limitX, nextX));
  y = Math.max(-limitY, Math.min(limitY, nextY));
  paint();
}}
viewport.addEventListener('keydown', event => {{
  if (event.target !== viewport || zoom === 1) return;
  const offset = {{ArrowLeft: [40, 0], ArrowRight: [-40, 0], ArrowUp: [0, 40], ArrowDown: [0, -40]}}[event.key];
  if (!offset) return;
  event.preventDefault();
  pan(x + offset[0], y + offset[1]);
}});
stage.querySelector('.controls').addEventListener('click', event => {{
  const button = event.target.closest('button');
  if (!button || button.getAttribute('aria-disabled') === 'true') return;
  switch(button.dataset.action) {{
    case 'in': setZoom(zoom + .25); break;
    case 'out': setZoom(zoom - .25); break;
    case 'reset': setZoom(1); viewport.scrollLeft = 0; break;
    case 'motion':
      manualMotion = stage.classList.contains('paused');
      try {{ sessionStorage.setItem(motionKey, manualMotion ? 'on' : 'off'); }} catch {{}}
      syncMotion();
      break;
  }}
}});
function point(event) {{
  return new DOMPoint(event.clientX, event.clientY).matrixTransform(canvas.getScreenCTM().inverse());
}}
canvas.addEventListener('pointerdown', event => {{
  if (event.button !== 0 || zoom === 1 || event.target.closest('.map-node')) return;
  drag = {{start: point(event), x, y, id: event.pointerId}};
  stage.classList.add('dragging');
  canvas.setPointerCapture(event.pointerId);
}});
canvas.addEventListener('pointermove', event => {{
  if (!drag || event.pointerId !== drag.id) return;
  const at = point(event);
  pan(drag.x + at.x - drag.start.x, drag.y + at.y - drag.start.y);
}});
for (const type of ['pointerup', 'pointercancel', 'lostpointercapture']) {{
  canvas.addEventListener(type, event => {{
    if (drag?.id !== event.pointerId) return;
    drag = null;
    stage.classList.remove('dragging');
  }});
}}
reduced.addEventListener('change', syncMotion);
syncMotion();
select(nodes[{selected}]); paint();
</script></html>"""
    st.iframe(view)
    hypotheses = [item for item in analysis["model"]["links"]
                  if analysis["stats"][focus]["name"] in (item["a"], item["b"])]
    if hypotheses:
        with st.expander("Model link hypotheses"):
            for item in hypotheses:
                st.text(f"{item['a']} ↔ {item['b']} · {item['hops']} hops · model output {item['score']:.2f}")



TABLE_OPTIONS = {
    "cdr_calls": "Telecom · CDR",
    "ipdr_cgnat": "Telecom · IPDR / CGNAT",
    "bank_ledger": "Bank ledger",
    "suspect_master": "Suspect profiles",
    "tower_locations": "Cell tower records",
    "source_archive": "Source archive · photos, audio and documents",
}


@st.dialog("Import evidence", width="large")
def upload_dialog(case):
    if case.station:
        case.station.require(case.identity, "import")
    st.caption("Import one schema per batch. Use UTF-8 CSV, TSV, JSON, JSONL, XLSX or structured text PDF. "
               "Photos, audio and other archive files retain their original bytes for export.")
    table = st.selectbox("Evidence type", TABLE_OPTIONS, format_func=TABLE_OPTIONS.get)
    with st.expander("Supported fields and aliases"):
        if table in SCHEMAS:
            st.text("Required: " + ", ".join(REQUIRED[table].split()))
            for field in SCHEMAS[table]:
                st.text(f"{field}" + (f" · {ALIASES[field].replace(' ', ', ')}" if field in ALIASES else ""))
            st.caption("Naive timestamps use IST. XLSX requires headers on the first row of each populated sheet. "
                       "Bank PDFs require extractable, consistently aligned columns and headers on each page.")
        else:
            st.caption("Archived files are included in the evidence bundle with their SHA-256 checksums.")
    uploads = st.file_uploader("Source files", accept_multiple_files=True)
    mapping, operator, observation = {}, None, "caller"
    if table in {"cdr_calls", "ipdr_cgnat"}:
        operator = st.selectbox("Operator if absent from the file", [None, "Airtel", "Jio 5G", "Vi", "BSNL"],
                                format_func=lambda x: x or "Read from file", key="import_operator")
        if table == "cdr_calls":
            observation = st.selectbox("Party observed by tower and device fields", ["caller", "callee"],
                                       help="A mapped observed-number column takes precedence.", key="observation_party")
        if uploads and len(uploads) == 1:
            with st.expander("Map source columns"):
                try:
                    file = uploads[0]
                    raw = file.getvalue()
                    if len(raw) > MAX_BYTES:
                        raise ValueError("Source exceeds the 32 MiB file limit.")
                    _, first = next(iter(read_upload(file.name, raw)), (None, {}))
                    if not first:
                        raise ValueError("No data rows available for mapping.")
                    st.caption("Automatic mapping recognizes common operator headings. Select a source column to override a field.")
                    for field in SCHEMAS[table]:
                        chosen = st.selectbox(field, [None, *first], format_func=lambda x: x or "Automatic",
                                              key=f"column_{table}_{sha(raw)[:12]}_{field}")
                        if chosen:
                            mapping[field] = chosen
                except (ValueError, UnicodeError, csv.Error, zipfile.BadZipFile) as error:
                    st.warning(str(error))
    if st.button("Ingest batch", type="primary", disabled=not uploads):
        successes, errors = [], []
        for item in uploads:
            try:
                count = case.ingest(table, item.name, item.getvalue(), retain=table == "source_archive",
                                    mapping=mapping, operator=operator, observation=observation)
                successes.append(f"{item.name} · {count:,} normalized rows" if count else f"{item.name} · original preserved")
            except Exception as error:
                errors.append(f"{item.name} · {error}")
                case.activity("import_rejected", source_sha256=sha(item.getvalue()), record_type=table)
        for message in successes:
            st.success(message)
        for message in errors:
            st.error(message)
        if successes:
            st.session_state["copilot_result"] = None
            st.session_state["nat_result"] = None
            st.session_state.pop("telecom_result", None)
            st.session_state.pop("report_result", None)
            st.session_state["import_done"] = True
    if st.session_state.get("import_done") and st.button("Return to workstation"):
        st.session_state["import_done"] = False
        st.rerun()


def money_text(amount):
    return f"₹{amount:,.2f}"


def result_rows(rows, kind):
    if not rows:
        return
    if len(rows) > 100:
        st.caption("Showing the first 100 matching rows.")
    records = []
    for row in rows[:100]:
        timestamp = display_time(row["timestamp"])
        if kind == "bank":
            records.append({"Hop": row["hop"], "Time (IST)": timestamp,
                            "From": f"{row['sender_name'] or '—'} · {row['sender_acc']}",
                            "To": f"{row['receiver_name'] or '—'} · {row['receiver_acc']}",
                            "Amount": money_text(row["amount_inr"]), "Transaction": row["txn_id"],
                            "Status": row["status"] or "—", "Source proof": proof(row)})
        elif kind == "tower":
            records.append({"Time (IST)": timestamp, "Caller": row["caller_msisdn"],
                            "Callee": row["callee_msisdn"], "Tower": row["cell_tower_id"],
                            "Carrier": row["telco"] or "—", "Source proof": proof(row)})
    st.dataframe(records, hide_index=True, width="stretch")


@st.dialog("Bank transactions", width="large")
def bank_dialog(case):
    people = sorted({r["name"] for r in case.all("suspect_master") if r["name"]})
    if not people:
        st.info("Import suspect profiles to filter the ledger by person.")
        return
    name = st.selectbox("Account holder", people, index=people.index("Rohan Mehta") if "Rohan Mehta" in people else 0)
    try:
        rows = bank_trail(case, name, 101)
        audit_query(case, "bank transactions", rows=len(rows))
    except ValueError as error:
        st.warning(str(error))
        return
    if not rows:
        st.info("No outbound transfers matched this name.")
        return
    st.caption("Hop 2 uses the receiving account label, name and transaction order. Trace continuity requires corroboration.")
    result_rows(rows, "bank")


@st.dialog("Tower inspection", width="large")
def tower_dialog(case):
    towers = case.all("tower_locations")
    if not towers:
        st.info("Import tower records to view coordinates.")
        return
    default = 0
    index = st.selectbox("Sector", range(len(towers)), index=default,
                         format_func=lambda i: f'{towers[i]["tower_name"]} · {towers[i]["tower_id"]}')
    row = towers[index]
    lat, lon, angle = row["lat"], row["lon"], row["azimuth_degrees"]
    bearing = f"{angle:g}° true" if angle is not None else "Unavailable"
    st.text(f"Latitude {lat:.5f}  |  Longitude {lon:.5f}  |  Azimuth {bearing}")
    st.text(proof(row))
    st.caption("Coordinates describe the tower. Shared serving sectors indicate overlapping coverage observations.")
    x, y = 84 + 51 * math.sin(math.radians(angle or 0)), 78 - 51 * math.cos(math.radians(angle or 0))
    if angle is not None:
        st.iframe(f"""<!doctype html><html lang="en"><title>Tower azimuth diagram</title><style>body{{margin:0}}</style>
<svg viewBox="0 0 168 156" role="img" aria-label="Tower sector bearing {angle:g} degrees"
style="display:block;width:168px;max-width:100%;margin:8px auto">
<circle cx="84" cy="78" r="55" fill="#0d1930" stroke="#315070"/>
<path d="M84 24V132M29 78H139" stroke="#24415d"/>
<text x="84" y="17" fill="#b8cbe2" text-anchor="middle" font-size="12">N</text>
<line x1="84" y1="78" x2="{x:.2f}" y2="{y:.2f}" stroke="#38bdf8" stroke-width="3"/>
<circle cx="84" cy="78" r="4" fill="#38bdf8"/><circle cx="{x:.2f}" cy="{y:.2f}" r="3" fill="#38bdf8"/></svg></html>""")
    seen = case.query("""SELECT * FROM cdr_calls WHERE cell_tower_id=?
                         ORDER BY timestamp,source_sha,source_locator LIMIT 101""", [row["tower_id"]])
    if seen:
        result_rows(seen, "tower")
    else:
        st.info("No CDR observations use this tower ID.")


@st.dialog("Evidence custody and Section 63 export", width="large")
def export_dialog(case, analysis):
    if case.station:
        case.station.require(case.identity, "export")
    st.caption("The worksheet is unsigned. The party and expert complete and sign the prescribed certificate. "
               "Download the evidence ZIP for original bytes, normalized records, model output and the custody chain.")
    document, files, checksums, head = certificate(case, analysis)
    st.code(head, language=None)
    left, right = st.columns(2)
    with left:
        st.download_button("Download Section 63 worksheet", document, "section-63-worksheet.html",
                           "text/html", on_click=lambda: case.activity("section63_worksheet_exported"),
                           type="primary", width="stretch")
    with right:
        data = evidence_zip(document, files, checksums, head)
        st.download_button("Download evidence ZIP", data, "darpan-evidence.zip", "application/zip",
                           on_click=lambda: case.activity("evidence_bundle_exported"), width="stretch")
    st.dataframe([{"Archive member": file, "SHA-256": digest} for file, digest in checksums.items()],
                 hide_index=True, width="stretch")


def resolver_panel(case):
    with st.container(key="resolver"):
        section("CGNAT lookup", "Match an observed connection against logged IP allocations with ±50 ms tolerance.", page=True)
        with st.container(key="lookup_form"):
            with st.form("nat"):
                address, port, proto = st.columns([2.3, 1, 1])
                with address:
                    ip = st.text_input("Public IPv4", "157.34.12.89" if case.demo else "", key=case.key("nat_ip"))
                with port:
                    source_port = st.text_input("Source port", "44120" if case.demo else "", key=case.key("nat_port"))
                with proto:
                    protocol = st.selectbox("Protocol", ["Any", "TCP", "UDP"], index=1 if case.demo else 0, key=case.key("nat_protocol"))
                time_col, submit = st.columns([2.6, 1], vertical_alignment="bottom")
                with time_col:
                    incident = st.text_input("Incident time (IST)", f"{DEMO_DATE} 02:18:42.110" if case.demo else "",
                                             placeholder="YYYY-MM-DD HH:MM:SS.sss", key=case.key("nat_incident"))
                with submit:
                    submitted = st.form_submit_button("Resolve subscriber", type="primary", width="stretch")
        if submitted:
            try:
                st.session_state["nat_result"] = case.resolve(ip, source_port.strip(), incident, protocol)
                audit_query(case, "CGNAT lookup", outcome=st.session_state["nat_result"][0],
                            rows=len(st.session_state["nat_result"][1]))
            except ValueError as error:
                st.session_state["nat_result"] = None
                st.error(str(error))
        result = st.session_state.get("nat_result")
        if result:
            status, rows, stamp = result
            if status == "Unique logged subscriber":
                st.success(status)
            elif rows:
                st.warning(status)
            else:
                st.info(status)
            st.caption(stamp)
            for row in rows[:12]:
                st.text(f'{row["telco"] or "Carrier unavailable"} · {row["caller_msisdn"] or "MSISDN unavailable"}')
                st.text(f'IMSI {row["imsi"] or "—"} | IMEI {row["imei"] or "—"}')
                st.caption(f'{display_time(row["session_start"])} – {display_time(row["session_end"])}')
                st.caption(proof(row))
                if row["application"] or row["service"] or row["destination_host"]:
                    st.caption("Supplied indicators · " + " / ".join(str(x) for x in
                               (row["application"], row["service"], row["destination_host"]) if x))
            if len(rows) > 12:
                st.caption(f"{len(rows):,} rows matched. Showing the first 12.")


def count_evidence(case):
    result = {table: case.query(f"SELECT count(*) AS total FROM {table}")[0]["total"] for table in SCHEMAS}
    return (
        ("Call records", result["cdr_calls"]),
        ("IP allocations", result["ipdr_cgnat"]),
        ("Transactions", result["bank_ledger"]),
        ("Suspect profiles", result["suspect_master"]),
        ("Cell towers", result["tower_locations"]),
        ("Original attachments", sum(source["table"] == "source_archive" for source in case.sources.values())),
    )


def evidence_summary(case):
    with st.container(key="source_summary"):
        total = len(case.sources)
        section("Source summary", f"{total:,} hashed source {'file' if total == 1 else 'files'}")
        rows = "".join(f'<tr><td>{label}</td><td class="num">{count:,}</td></tr>'
                       for label, count in count_evidence(case))
        st.html('<table class="ledger" aria-label="Evidence counts"><thead><tr>'
                '<th scope="col">Record type</th><th scope="col" class="num">Count</th>'
                '</tr></thead><tbody>' + rows + "</tbody></table>")


def sources_panel(case):
    with st.container(key="sources"):
        count = len(case.sources)
        section("Source ledger", f"{count:,} files with SHA-256 checksums" if count else None, page=True)
        if not count:
            st.info("This case is empty. Use Import evidence to add records or retain original attachments.")
            return
        if case.demo:
            st.caption("These files belong to the synthetic case. Switch to Local evidence to import files.")
        with st.container(key="source_index"):
            rows = []
            for digest, source in case.sources.items():
                label = "Original attachment" if source["table"] == "source_archive" else TABLE_OPTIONS[source["table"]]
                rows.append(f'<tr><td>{esc(source["name"])}</td><td>{esc(label)}</td>'
                            f'<td class="num">{source["rows"]:,}</td><td class="num">{source["bytes"]:,}</td>'
                            f'<td class="digest" title="{digest}">{digest[:16]}…</td></tr>')
            st.html('<div class="table-wrap" tabindex="0" role="region" aria-label="Source ledger table">'
                    '<table class="ledger"><thead><tr><th scope="col">Source file</th><th scope="col">Record type</th>'
                    '<th scope="col" class="num">Rows</th><th scope="col" class="num">Bytes</th>'
                    '<th scope="col">SHA-256 prefix</th></tr></thead><tbody>' + "".join(rows) + "</tbody></table></div>")
        with st.expander("Import validation and mappings"):
            details = [{"File": item["name"], "Imported rows": item["rows"],
                        "Missing values": ", ".join(f"{k}: {v}" for k,v in sorted(item.get("missing",{}).items())) or "None reported",
                        "Column overrides": ", ".join(f"{k} ← {v}" for k,v in item.get("mapping",{}).items()) or "Automatic",
                        "Observation party": item.get("observation"),
                        "SHA-256": digest} for digest,item in case.sources.items()]
            st.dataframe(details,hide_index=True,width="stretch")


def topology_panel(case, analysis):
    with st.container(key="topology"):
        ranking = analysis["ranking"]
        if not ranking:
            st.info("Import suspect profiles and related records to build the evidence network.")
            return
        focus_col, layer_col = st.columns([1, 1])
        with focus_col:
            focus = st.selectbox("Focus person", ranking, key=case.key("graph_subject"),
                                 format_func=lambda key: analysis["stats"][key]["name"])
        with layer_col:
            layer = st.selectbox("Evidence layer", ["Overview", "Accounts", "Devices & phones", "Tower observations"],
                                 key=case.key("graph_layer"))
        graph_view(analysis, focus, layer)


def ranking_panel(case, analysis):
    with st.container(key="rank"):
        ordered = analysis["ranking"]
        scored = any(analysis["stats"][key]["score"] is not None for key in ordered)
        section("Suspect ranking" if scored else "Suspect profiles",
                "Synthetic model scores" if scored else "Profiles with available source rows")
        if not ordered:
            st.caption("No suspect profiles in this case.")
            return
        rows = []
        for key in ordered[:5]:
            row = analysis["stats"][key]
            calls, _, _, _, coloc, _ = row["features"]
            coloc_text = f"{coloc:.0%} shared sector" if row["observations"] else "No tower data"
            account_count = row["shared_accounts"]
            score = f'{row["score"]:.1f}%' if row["score"] is not None else "—"
            score_cell = f'<td class="num score">{score}</td>' if scored else ""
            rows.append(f'<tr><td><strong>{esc(row["name"])}</strong>'
                        f'<span class="row-meta">{account_count} shared accounts · {esc(coloc_text)}</span></td>'
                        f'<td class="num">{calls:,}</td>{score_cell}</tr>')
        score_heading = '<th scope="col" class="num">Score</th>' if scored else ""
        st.html('<table class="ledger" aria-label="Suspect evidence summary"><thead><tr>'
                '<th scope="col">Name</th><th scope="col" class="num">Calls</th>' + score_heading +
                '</tr></thead><tbody>' + "".join(rows) + "</tbody></table>")
        with st.expander("Inspect features and proof"):
            key = st.selectbox("Profile", ordered, key=case.key("rank_profile"),
                               format_func=lambda item: analysis["stats"][item]["name"])
            row = analysis["stats"][key]
            st.dataframe([{"Feature": name, "Value": f"{value:,.4g}"}
                          for name, value in zip(FEATURE_NAMES, row["features"])], hide_index=True)
            for citation in row["citations"][:5]:
                st.caption(citation)
            if scored:
                model = analysis["model"]
                origin = model.get("origin", "Trained locally")
                st.caption(f"{origin} · {model['epochs']} training epochs · {model['seconds']:.2f}s CPU analysis.")


def copilot_panel(case):
    with st.container(key="copilot"):
        section("Evidence assistant", "Ask about recorded contacts, tower visits, device changes or a case time window.", page=True)
        numbers, label = subject_options(case)
        first, other = st.columns(2)
        active = first.selectbox("Default case number", [None,*numbers], index=1 if numbers else 0,
                                 format_func=lambda n:label(n) if n else "Specify in question", key=case.key("assistant_number"))
        compare_choices = [n for n in numbers if n != active]
        compare = other.selectbox("Default comparison number",[None,*compare_choices],
                                  format_func=lambda n:label(n) if n else "Specify in question",key=case.key("assistant_compare"))
        with st.container(key="search_form"):
            with st.form("officer_inquiry"):
                ask, send = st.columns([4, 1], vertical_alignment="bottom")
                with ask:
                    question = st.text_input("Question", placeholder="Which numbers do these suspects both contact?",
                                             max_chars=500, key=case.key("officer_question"))
                with send:
                    submitted = st.form_submit_button("Search evidence", width="stretch", type="primary")
            st.caption("English, Hindi or Hinglish. Use ISO dates and IST times to make time windows explicit.")
        with st.expander("Questions and follow-up filters"):
            st.write("Show top contacts · Who did this suspect call last? · Compare common numbers · Show tower timeline · Show IMEI and SIM changes · Summarize the case")
            st.write("Add a date or a time range, for example 2026-01-14 02:00 to 04:00 IST.")
        if submitted:
            st.session_state["copilot_result"] = None
            if question.strip():
                try:
                    finding = telecom.answer(case, question,active,compare,predicted=classify_question(question))
                    if finding is None:
                        title,rows,kind=resolve_question(case,question)
                        if kind=="other":
                            title="The assistant could not match this question to a supported evidence analysis. Try a case number and a specific contact, tower, device or time-window question."
                        result=(title,rows,kind)
                        count=len(rows)
                    else:
                        result=(finding.title, finding, "finding")
                        count=len(finding.evidence)
                    st.session_state["copilot_result"] = result
                    audit_query(case,"assistant",question_sha256=sha(question.encode()),rows=count)
                except ValueError as error:
                    st.warning(str(error))
            else:
                st.info("Enter an evidence question.")
        result = st.session_state.get("copilot_result")
        if result:
            title, rows, kind = result
            if kind == "finding":
                show_finding(rows)
            elif rows:
                section(title)
                result_rows(rows, kind)
            else:
                st.info(title if (kind == "other" or title.endswith((".", "।"))) else title + " · No matching rows")
        section("Browse records")
        bank, tower = st.columns(2)
        if bank.button("Bank transactions", width="stretch"):
            bank_dialog(case)
        if tower.button("Tower coordinates", width="stretch"):
            tower_dialog(case)


def draw_visits(visits, selected):
    mapped = [row for row in visits if row["Latitude"] is not None]
    if not mapped:
        st.info("No matching tower coordinates are available. Review the timeline rows and import a tower file.")
        return
    coordinates = {r["Tower ID"]: (r["Latitude"], r["Longitude"]) for r in mapped}
    lo, hi = min(v[1] for v in coordinates.values()), max(v[1] for v in coordinates.values())
    bottom, top = min(v[0] for v in coordinates.values()), max(v[0] for v in coordinates.values())
    mean_lat = math.radians((top + bottom) / 2)
    factor = max(.02, math.cos(mean_lat))
    span = max((hi-lo)*factor/690, (top-bottom)/265, .000005)
    points = {key: (400+(lon-(lo+hi)/2)*factor/span, 180-(lat-(bottom+top)/2)/span)
              for key, (lat,lon) in coordinates.items()}
    routes = []
    for a,b in zip(visits,visits[1:]):
        if a["Tower ID"] not in points or b["Tower ID"] not in points:
            continue
        x,y = points[a["Tower ID"]]
        x2,y2 = points[b["Tower ID"]]
        active = b["Visit"] == selected
        routes.append(f'<path d="M{x:.1f},{y:.1f} L{x2:.1f},{y2:.1f}" fill="none" '
                      f'stroke="{("#ffd48f" if active else "#568e91")}" stroke-width="{3 if active else 1.3}" '
                      f'stroke-dasharray="4 4" marker-end="url(#arrow)"/>')
    nodes = []
    active_id = visits[selected-1]["Tower ID"]
    for key,(x,y) in points.items():
        active = key == active_id
        fill = "#ffd48f" if active else "#85e4d6"
        nodes.append(f'<g><title>{esc(key)}</title><circle cx="{x:.1f}" cy="{y:.1f}" r="{8 if active else 5}" '
                     f'fill="{fill}"/><text x="{x:.1f}" y="{y+25:.1f}" fill="#ecf6f1" font-size="13" '
                     f'text-anchor="middle">{esc(key)}</text></g>')
    active = visits[selected-1]
    header = f"Visit {selected} of {len(visits)} · {active['Tower']} · {active['First (IST)']}"
    st.iframe(f"""<!doctype html><html lang="en"><meta charset="utf-8"><title>Serving tower map</title>
<style>html,body{{margin:0;overflow:hidden;background:#101c22;color:#ecf6f1;font:14px system-ui}}
svg{{display:block;width:100%;height:340px}}
p{{margin:0;padding:10px 14px;border-bottom:1px solid #345057}}</style><p>{esc(header)}</p>
<svg viewBox="0 0 800 360" role="img" aria-label="Serving tower locations and links ordered by observation time">
<defs><pattern id="grid" width="38" height="38" patternUnits="userSpaceOnUse">
<path d="M 38 0 L 0 0 0 38" fill="none" stroke="#223940"/></pattern>
<marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
<path d="M0,0 L7,3 L0,6" fill="#85e4d6"/></marker></defs>
<rect width="800" height="360" fill="url(#grid)"/>
<text x="24" y="30" fill="#a3bcbf" font-size="13">N ↑</text>
<text x="24" y="339" fill="#a3bcbf" font-size="13">Relative coordinates · serving towers · no GPS route</text>
{''.join(routes)}{''.join(nodes)}</svg></html>""", height=400)


def show_finding(finding):
    section(finding.title)
    st.write(finding.summary)
    if finding.rows:
        st.dataframe(finding.rows[:telecom.RESULT_LIMIT], hide_index=True, width="stretch")
    if finding.evidence:
        with st.expander(f"Source records ({len(finding.evidence):,})"):
            st.dataframe(finding.evidence[:telecom.RESULT_LIMIT], hide_index=True, width="stretch")
    if max(len(finding.rows),len(finding.evidence)) > telecom.RESULT_LIMIT:
        st.caption(f"Showing up to {telecom.RESULT_LIMIT} rows per table. Excel exports include the full results.")


def contact_network(case, number, start, end):
    calls = telecom.calls_for(case, number, start, end)
    if not calls:
        st.info("No calls match this number and time range.")
        return
    groups = telecom.group_contacts(calls)
    graph = nx.Graph()
    graph.add_node(number, kind="phone", label=number)
    for peer, rows in groups.items():
        if peer == number:
            continue
        graph.add_node(peer, kind="phone", label=peer)
        citations = [proof(rows[0])]
        if len(rows) > 1:
            citations.append(proof(rows[-1]))
        graph.add_edge(number, peer, count=len(rows), kind={"Recorded call"},
                       proofs={f"{len(rows)} recorded calls": citations})
    analysis = {"graph": graph, "model": {"links": []},
                "stats": {number: {"name": number, "score": None, "citations": [proof(calls[0])]}}}
    graph_view(analysis, number, "Calls")
    st.caption("The map shows up to nine direct contacts by recorded call count. Open the source rows for the complete evidence.")


def subject_options(case):
    numbers = telecom.subjects(case)
    profiles = {entry["phone"]: entry["name"] for entry in case.all("suspect_master")}
    return numbers, lambda number: f"{profiles[number]} · {number}" if number in profiles else number


def audit_query(case, workflow, **details):
    if case.station:
        case.station.require(case.identity, "query")
    case.activity("query_run", workflow=workflow, **details)


def telecom_panel(case):
    section("Telecom analysis", "Compare numbers, inspect communication activity and review serving tower observations.", page=True)
    numbers, label = subject_options(case)
    if not numbers:
        st.info("Import a CDR, IPDR or suspect profile file to select a case number.")
        return
    controls = st.columns(3)
    with controls[0]:
        number = st.selectbox("Case number A", numbers, format_func=label, key=case.key("telecom_a"))
    with controls[1]:
        compare = st.selectbox("Case number B", [n for n in numbers if n != number],
                               index=0 if len(numbers)>1 else None, format_func=label, key=case.key("telecom_b"))
    views = ("Contact network", "Contact activity", "Common contacts", "Tower timeline",
             "Handset and SIM", "Night activity", "Case summary", "IPDR service indicators")
    with controls[2]:
        view = st.selectbox("Analysis", views, key=case.key("telecom_view"))
    with st.expander("Time filter"):
        left,right = st.columns(2)
        start_raw = left.text_input("From (IST)", placeholder="2026-01-14 00:00:00", key=case.key("telecom_start"))
        end_raw = right.text_input("Until (IST, exclusive)", placeholder="2026-01-15 00:00:00", key=case.key("telecom_end"))
    if st.button("Run analysis", type="primary", key="telecom_run"):
        try:
            start, end = (as_time(start_raw),as_time(end_raw)) if start_raw.strip() or end_raw.strip() else (None,None)
            if start is not None and end <= start:
                raise ValueError("The end of the time filter must be after the start.")
            choices = {
                "Contact network": lambda: telecom.contacts(case, number,start,end),
                "Contact activity": lambda: telecom.contacts(case, number,start,end),
                "Common contacts": lambda: telecom.common_contacts(case, number,compare,start,end) if compare
                                    else telecom.Finding("Common contacts", "Choose a second case number."),
                "Tower timeline": lambda: telecom.movement(case, number,start,end),
                "Handset and SIM": lambda: telecom.device_changes(case, number,start,end),
                "Night activity": lambda: telecom.contacts(case, number,start,end,mode="night"),
                "Case summary": lambda: telecom.case_summary(case, number,start,end),
                "IPDR service indicators": lambda: telecom.ipdr_activity(case, number,start,end),
            }
            result = choices[view]()
            audit_query(case, view, rows=len(result.evidence), subject_sha256=sha(number.encode()))
            st.session_state["telecom_result"] = (view, number, start, end, result)
            st.session_state.pop(case.key("map_visit"), None)
        except ValueError as error:
            st.session_state.pop("telecom_result",None)
            st.error(str(error))
    saved = st.session_state.get("telecom_result")
    if saved is None:
        st.caption("Select the analysis and run it to see results with source references.")
        return
    chosen, selected, start, end, result = saved
    if chosen == "Contact network":
        contact_network(case, selected, start, end)
    if chosen == "Tower timeline" and result.rows:
        step = st.slider("Observation step", 1,len(result.rows), key=case.key("map_visit")) if len(result.rows)>1 else 1
        draw_visits(result.rows,step)
    show_finding(result)


def report_panel(case):
    section("Reports and review", "Create draft reports for officer review. Every section includes source references.", page=True)
    numbers, label = subject_options(case)
    if case.review:
        st.success(f"Officer review recorded by {case.review['reviewer']} on {case.review['at']}.")
    else:
        st.info("Review pending. Analytical leads require officer verification.")
    if numbers:
        select = st.selectbox("Report subject",numbers,format_func=label,key=case.key("report_subject"))
        choices = [n for n in numbers if n != select]
        compare = st.selectbox("Compare with", [None,*choices],format_func=lambda n:label(n) if n else "No comparison",key=case.key("report_compare"))
        if st.button("Build draft report",type="primary"):
            findings = [telecom.contacts(case, select), telecom.movement(case, select),
                        telecom.device_changes(case,select),telecom.ipdr_activity(case,select)]
            if compare:
                findings.insert(1,telecom.common_contacts(case,select,compare))
            title = f"Darpan PS03 investigation report · {select}"
            audit_query(case,"draft report",subject_sha256=sha(select.encode()))
            st.session_state["report_result"] = (title,findings)
        draft = st.session_state.get("report_result")
        if draft is not None:
            title, findings = draft
            st.write(title)
            left, right = st.columns(2)
            left.download_button("Download draft PDF",telecom.build_pdf(title,findings),"darpan-draft.pdf","application/pdf",
                                 on_click=lambda: case.activity("report_exported",format="pdf"),width="stretch")
            right.download_button("Download draft Excel",telecom.build_xlsx(title,findings),"darpan-draft.xlsx",
                                  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                  on_click=lambda: case.activity("report_exported",format="xlsx"),width="stretch")
    if case.station and case.station.allows(case.identity,"review"):
        with st.form("review_form"):
            note=st.text_area("Review observations",max_chars=600)
            checked=st.checkbox("I reviewed the underlying source records.")
            saved=st.form_submit_button("Record officer review")
        if saved:
            if not checked or not note.strip():
                st.warning("Confirm source review and enter a note.")
            else:
                previous=case.review
                mark=len(case.events)
                case.review={"reviewer":case.identity["username"],"at":display_time(datetime.now(UTC)),"note":note.strip()}
                case.append_event("officer_reviewed",case.review)
                try:
                    case.save("review")
                except (ValueError,PermissionError) as error:
                    case.review=previous
                    del case.events[mark:]
                    st.error(str(error))
                else:
                    case.activity("officer_reviewed")
                    st.rerun()
    if case.review:
        st.caption(case.review["note"])
    with st.expander("Case activity"):
        if case.station:
            entries=case.station.activity(case.identity,case_id=case.case_id)
        else:
            entries=[{"Sequence":event["index"],"Action":event["action"],
                      "Time (IST)":display_time(event["at"]),"Hash":event["hash"][:16]} for event in reversed(case.events)]
        if entries:
            st.dataframe(entries,hide_index=True,width="stretch")
        else:
            st.caption("No visible activity recorded.")


def protected_case():
    section("Protected case workspace", "Use a station account to open encrypted evidence cases.", page=True)
    try:
        station=vault.Station(vault.station_path(),os.getenv("DARPAN_KEY_FILE"))
    except (OSError,ValueError):
        st.info("The station vault is not initialized. Run python app.py --create-account --username investigator --role investigator to set up a station account.")
        st.stop()
    identity=st.session_state.get("station_identity")
    if identity and time.monotonic()-identity["last_seen"]>1800:
        st.session_state.pop("station_identity",None)
        st.session_state.pop("vault_case",None)
        identity=None
    if not identity:
        with st.form("station_login"):
            user=st.text_input("Station username",max_chars=64)
            password=st.text_input("Password",type="password",max_chars=1024)
            submit=st.form_submit_button("Sign in",type="primary")
        if submit:
            auth=station.authenticate(user,password)
            if auth:
                st.session_state["station_identity"]=dict(auth,last_seen=time.monotonic())
                st.rerun()
            st.error("Sign-in failed. Check your credentials or wait before retrying.")
        st.stop()
    identity["last_seen"]=time.monotonic()
    title,logout=st.columns([3,1])
    title.caption(f"{identity['username']} · {identity['role']}")
    if logout.button("Sign out",width="stretch"):
        station.log(identity["username"],"logout")
        for key in list(st.session_state):
            if key not in {"demo_case_v3","local_mode"}:
                del st.session_state[key]
        st.rerun()
    if station.allows(identity,"create"):
        with st.expander("Create protected case"):
            with st.form("create_station_case"):
                name=st.text_input("Case reference",max_chars=100)
                create=st.form_submit_button("Create case")
            if create and name.strip():
                new=Case()
                case_id, revision=station.create(identity,name.strip(),new.payload())
                st.session_state["vault_choice"]=case_id
                st.session_state.pop("vault_case",None)
    listing=dict(station.list_cases(identity))
    if not listing:
        st.info("There are no cases in this station vault.")
        st.stop()
    selected=st.selectbox("Protected case",list(listing),format_func=listing.get,key="vault_choice")
    if st.button("Reload case from vault"):
        st.session_state.pop("vault_case",None)
    cached=st.session_state.get("vault_case")
    if cached is None or cached.case_id != selected:
        revision,payload=station.load(identity,selected)
        cached=Case.from_payload(payload)
        cached.station,cached.identity,cached.case_id,cached.revision=station,identity,selected,revision
        st.session_state["vault_case"]=cached
        st.session_state.pop("active_case",None)
    return cached,listing[selected]


def main():
    st.set_page_config(page_title="Darpan Forensics", page_icon="◎", layout="wide",
                       initial_sidebar_state="collapsed", menu_items={})
    st.set_option("client.showErrorDetails", "none")
    torch.set_num_threads(1)
    st.html(CSS)
    st.html(f"""<header class="masthead">
<div class="wordmark"><img alt="" src="{FINGERPRINT_URI}" width="23" height="23">Darpan Forensics</div>
<div class="station-meta">Offline workstation · v{VERSION}</div></header>""")
    with st.container(key="case_controls"):
        name, mode, actions = st.columns([3, 1, 1.1], vertical_alignment="center")
        with mode:
            local_mode = st.toggle("Local evidence", key="local_mode", help="Switch between the synthetic and local cases.")
        if local_mode:
            case, reference = protected_case()
            case_key = case.case_id
        else:
            case_key, reference = "demo_case_v3", "Case PS03"
            if case_key not in st.session_state:
                st.session_state[case_key] = make_demo()
            case = st.session_state[case_key]
        if st.session_state.get("active_case") != case_key:
            st.session_state["active_case"] = case_key
            for key in ("copilot_result", "nat_result", "nat_ip", "nat_port", "nat_protocol", "nat_incident",
                        "graph_subject", "graph_layer", "rank_profile", "officer_question",
                        "telecom_result","report_result","telecom_a","telecom_b","telecom_start","telecom_end","map_visit",
                        "assistant_number","assistant_compare","report_subject","report_compare"):
                st.session_state.pop(key, None)
        analysis = case.analysis or analyze(case)
        with name:
            label = "Protected local case" if local_mode else "Rajasthan Police Hackathon 2026"
            context = "Encrypted station vault" if local_mode else "Synthetic case · 14 January 2026"
            st.html(f'<div class="eyebrow">{label}</div><h1 class="case-title">{esc(reference)}</h1>'
                    f'<p class="section-detail">{context}</p>')
        with actions:
            if local_mode and case.station.allows(case.identity,"import") and st.button("Import evidence", width="stretch"):
                st.session_state["import_done"] = False
                upload_dialog(case)
            if st.button("Export evidence", width="stretch"):
                export_dialog(case, analysis)
    with st.container(key="workspace"):
        network, analysis_tab, sources, lookup, search, reports = st.tabs(
            ["Network", "Telecom", "Sources", "IP lookup", "Assistant", "Reports"], key="case_views")
        with network:
            with st.container(key="network_title"):
                heading, sizing = st.columns([3.2, 1.15], vertical_alignment="center")
                with heading:
                    section("Evidence network", page=True)
                with sizing:
                    expanded = st.toggle("Expand map", key="map_expanded")
            if expanded:
                topology_panel(case, analysis)
                with st.expander("Source summary and suspect profiles"):
                    source_col, profile_col = st.columns(2)
                    with source_col:
                        evidence_summary(case)
                    with profile_col:
                        ranking_panel(case, analysis)
            else:
                canvas, sidebar = st.columns([2.8, 1.15])
                with canvas:
                    topology_panel(case, analysis)
                with sidebar:
                    with st.container(key="rail"):
                        ranking_panel(case, analysis)
                        evidence_summary(case)
        with sources:
            sources_panel(case)
        with analysis_tab:
            telecom_panel(case)
        with lookup:
            resolver_panel(case)
        with search:
            copilot_panel(case)
        with reports:
            report_panel(case)
    now = datetime.now(IST).strftime("%d %b %Y · %H:%M IST")
    st.html(f'<footer class="footer"><span>Mega Larpers · {len(case.events)} custody events</span>'
            f'<span>{esc(now)}</span></footer>')


def train_models_cli(args):
    parser = argparse.ArgumentParser(description="Train both Darpan models locally from seeded tensors.")
    parser.add_argument("--output", type=Path, default=models.CHECKPOINT, help="Path for the JSON checkpoint")
    destination = parser.parse_args(args).output
    torch.set_num_threads(1)
    case = make_demo()
    analyze(case, train_to=destination)
    checkpoint_sha = sha(destination.read_bytes())
    print(f"Trained and saved both CPU models to {destination.resolve()}")
    print(f"Checkpoint file SHA-256 {checkpoint_sha}")


def create_account_cli(args):
    parser = argparse.ArgumentParser(description="Create an account in the local encrypted Darpan station vault.")
    parser.add_argument("--station", type=Path, default=vault.station_path())
    parser.add_argument("--username", required=True)
    parser.add_argument("--role", choices=vault.ROLES, required=True)
    vault.setup_account(parser.parse_args(args))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--train-models":
        train_models_cli(sys.argv[2:])
    elif len(sys.argv) > 1 and sys.argv[1] == "--create-account":
        create_account_cli(sys.argv[2:])
    else:
        main()
