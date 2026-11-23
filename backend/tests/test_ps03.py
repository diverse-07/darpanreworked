import io
import secrets
import tempfile
import unittest
from pathlib import Path

from openpyxl import load_workbook
from pypdf import PdfReader

import app
import station_vault as vault
import telecom_analysis as t

N1 = "+919829077112"
N2 = "+919876543210"
SAMPLES = Path(__file__).resolve().parents[1] / "sample_data"


class PS03Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.torch.set_num_threads(1)

    def test_import_formats_and_quality(self):
        case = app.Case()
        for table, filename in (("cdr_calls", "Jio_CDR.csv"), ("cdr_calls", "Airtel_CDR.tsv"),
                                ("ipdr_cgnat", "Carrier_IPDR.csv")):
            self.assertGreater(case.ingest(table, filename, (SAMPLES / filename).read_bytes()), 0)
        self.assertEqual({row["telco"] for row in case.all("cdr_calls")}, {"Jio 5G", "Airtel"})
        bad = b"timestamp,caller,callee\nbad,xx,yy\nbad2,xx,zz"
        with self.assertRaisesRegex(ValueError, r"Row #2.*Row #3"):
            case.ingest("cdr_calls", "rejected.csv", bad)
        self.assertEqual(len(case.sources), 3)
        custom = b"call_start,a,b\n2026-01-01 10:20:30,9000000111,9000000222"
        case.ingest("cdr_calls", "custom.csv", custom,
                    mapping={"caller_msisdn": "a", "callee_msisdn": "b"}, observation="callee")
        self.assertEqual(case.all("cdr_calls")[0].keys() & {"observed_msisdn"}, {"observed_msisdn"})
        matching = [row for row in case.all("cdr_calls") if row["source_file"] == "custom.csv"]
        self.assertEqual(matching[0]["observed_msisdn"], "+919000000222")

    def test_analyses_and_grounded_assistant(self):
        case = app.make_demo()
        graph = app.analyze(case)
        self.assertEqual(graph["model"]["origin"], "Local checkpoint")
        self.assertEqual(len(t.common_contacts(case, N1, N2).rows), 2)
        self.assertEqual(len(t.movement(case, N1).rows), 4)
        self.assertEqual({row["Identifier"] for row in t.device_changes(case, N1).rows},
                         {"Handset IMEI", "SIM ICCID", "SIM IMSI"})
        cases = {
            "top contacts for Rohan Mehta": "Contact activity",
            "common numbers between Rohan Mehta and Aman Verma": "Common contacts",
            "show tower timeline for Rohan Mehta": "Serving tower timeline",
            "show IMEI and SIM changes for Rohan Mehta": "Handset and SIM observations",
            "calls between 2026-01-14 02:00 and 04:00 for Rohan Mehta": "Calls in the selected window",
            "show IPDR app usage for Rohan Mehta": "IPDR service indicators",
            "रोहन मेहता के टावर क्रम दिखाएं": "Serving tower timeline",
            "dono ke common numbers": "Common contacts",
            "summarize the case": "Case summary",
            "explain this contact graph": "Contact graph interpretation",
        }
        for question, title in cases.items():
            with self.subTest(question=question):
                result = t.answer(case, question, N1, N2, predicted=app.classify_question(question))
                self.assertEqual(result.title, title)
                self.assertTrue(result.evidence)
                self.assertTrue(any("Source record" in row for row in result.evidence))
        self.assertIsNone(t.answer(case, "who is guilty", N1))
        self.assertIn("no matching", t.contacts(case, "+911234567890").summary)
        self.assertEqual(case.resolve("157.34.12.89", "44120", "2026-01-14 02:18:42.110", "TCP")[0],
                         "Unique logged subscriber")
        self.assertEqual(case.resolve("157.34.12.89", "44120", "2026-01-14 02:18:42.060", "TCP")[0],
                         "Candidate needs clock or protocol corroboration")
        self.assertEqual(t.ipdr_activity(case, N1).rows[0]["Supplied application"], "Synthetic Messaging")

    def test_pdf_excel_and_custody(self):
        case = app.make_demo()
        findings = [t.contacts(case, N1), t.common_contacts(case, N1, N2), t.movement(case, N1)]
        pdf = PdfReader(io.BytesIO(t.build_pdf("Synthetic review", findings)))
        self.assertIn("Draft investigation report", pdf.pages[0].extract_text())
        excel = load_workbook(io.BytesIO(t.build_xlsx("Synthetic review", findings)))
        self.assertIn("01 Sources", excel.sheetnames)
        suspicious = t.Finding("Cell type test", "Fixture", [{"Value": "=1+1"}])
        sheets = load_workbook(io.BytesIO(t.build_xlsx("Safe", [suspicious])))
        self.assertEqual(sheets["01 Results"]["A2"].data_type, "s")
        document, files, digests, head = app.certificate(case, app.analyze(case))
        for filename, checksum in digests.items():
            self.assertEqual(app.sha(files[filename]), checksum)
        self.assertTrue(document and head)

    def test_assistant_first_and_last_calls(self):
        case = app.make_demo()
        reply = t.answer(case, "which number did suspect called lastly", active=N1)
        self.assertEqual(reply.title, "Last recorded outgoing call")
        self.assertEqual(reply.rows[0]["Other number"], "+919876543211")
        self.assertIn("2026-01-14 02:46:46", reply.rows[0]["Time (IST)"])
        self.assertIn("BSNL_CDR.csv Row #", reply.evidence[0]["Source record"])
        self.assertEqual(t.answer(case, "who last called the suspect", active=N1).rows[0]["Direction"], "Incoming")
        self.assertEqual(t.answer(case, "सबसे पहले किस नंबर पर कॉल की", active=N1).title, "First recorded outgoing call")
        self.assertEqual(t.answer(case, "first and last call", active=N1).rows[0]["Position"], "First")
        self.assertIsNone(t.boundary_request("calls last night"))
        self.assertIsNone(t.boundary_request("last 10 calls"))

        tied = app.Case()
        tied.ingest("cdr_calls", "Tied.csv", (
            "timestamp,caller,callee\n"
            "2026-01-14 09:00:00,9829077112,9876543210\n"
            "2026-01-14 09:00:00,9829077112,9876543211\n"
        ).encode())
        answer = t.answer(tied, "latest outgoing call", active=N1)
        self.assertEqual(len(answer.rows), 2)
        self.assertIn("share a boundary timestamp", answer.summary)
        self.assertFalse(t.answer(tied, "last incoming call", active=N1).rows)

    def test_assistant_call_count_and_pair_semantics(self):
        case = app.make_demo()
        question = "How many calls did Rohan Mehta make?"
        result = t.answer(case, question, N1, N2, predicted=app.classify_question(question))
        self.assertEqual(result.title, "Recorded call count")
        self.assertIn("47 recorded outgoing calls", result.summary)
        self.assertEqual(len(result.evidence), 47)
        self.assertEqual(app.resolve_question(case, question)[2], "other")
        result = t.answer(case, "Show the last call between Rohan Mehta and Aman Verma")
        self.assertEqual(result.title, "Last recorded call")
        self.assertEqual(result.rows[0]["Other number"], N2)
        result = t.answer(case, "Which numbers did Rohan Mehta and Aman Verma both call?")
        self.assertIn("both called 2 third-party numbers", result.summary)
        self.assertTrue(all(row["Direction"] == "Outgoing" for row in result.evidence
                            if row["Compared subject"] != "Direct A/B"))

    def test_encrypted_station_roles_and_concurrent_revisions(self):
        with tempfile.TemporaryDirectory() as directory:
            station = vault.Station(directory, bootstrap=True)
            password = secrets.token_urlsafe(20)
            station.add_account("fixture-officer", "investigator", password)
            station.add_account("fixture-reviewer", "reviewer", password)
            officer = station.authenticate("fixture-officer", password)
            reviewer = station.authenticate("fixture-reviewer", password)
            self.assertIsNone(station.authenticate("fixture-officer", "wrong"))
            case = app.Case()
            case.ingest("cdr_calls", "Jio_CDR.csv", (SAMPLES / "Jio_CDR.csv").read_bytes())
            case_id, revision = station.create(officer, "Synthetic station case", case.payload())
            self.assertNotIn(b"Jio_CDR.csv", station.database.read_bytes())
            revision, payload = station.load(reviewer, case_id)
            restored = app.Case.from_payload(payload)
            self.assertEqual(restored.all("cdr_calls"), case.all("cdr_calls"))
            with self.assertRaises(PermissionError):
                station.save(reviewer, case_id, revision, payload, "import")
            station.save(reviewer, case_id, revision, dict(payload, review={"note": "Checked fixture"}), "review")
            with self.assertRaises(ValueError):
                station.save(officer, case_id, revision, payload, "import")
            station.log(officer["username"], "query_run", case_id=case_id)
            self.assertTrue(any(row["Action"] == "query_run" for row in station.activity(reviewer, case_id=case_id)))
