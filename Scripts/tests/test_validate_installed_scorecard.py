import importlib.util
import base64
import json
import os
from pathlib import Path
import plistlib
import pwd
import subprocess
import sqlite3
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "Scripts" / "validate-installed-scorecard.py"
SPEC = importlib.util.spec_from_file_location("installed_scorecard", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class PrivilegedStoreDecodeTests(unittest.TestCase):
    def test_prevention_requires_matching_path_or_durable_denial(self):
        records = {"event": {"kind": "AUTH deny", "target": "/tmp/unrelated"}}
        self.assertIsNone(MODULE.matching_prevention({}, records, {"paths": []}))
        self.assertEqual(
            MODULE.matching_prevention({}, {}, {"paths": ["/tmp/fixture"], "endpointDenied": True})["kind"],
            "AUTH deny",
        )

    def test_plain_snapshot_is_rejected(self):
        with self.assertRaises(ValueError):
            MODULE.decode_privileged_store(b'{"incidents":[]}')

    def test_nonzero_exit_is_not_prevention_without_durable_record(self):
        self.assertEqual(MODULE.measured_status(None), "PASS")
        self.assertEqual(
            MODULE.measured_status({"kind": "quarantine", "target": "/tmp/eicar"}),
            "PREVENTED",
        )

    def test_file_deletion_is_detection_only_even_with_prevention_evidence(self):
        prevention = {"kind": "deny", "target": "/tmp/unrelated"}
        self.assertEqual(
            MODULE.measured_status(prevention, "T1070.004"),
            "DETECTED",
        )

    def test_quarantine_database_is_authoritative_prevention_evidence(self):
        with tempfile.TemporaryDirectory(prefix="nick-quarantine-test-") as directory:
            database_path = Path(directory) / "quarantine.db"
            with sqlite3.connect(database_path) as database:
                database.execute(
                    "CREATE TABLE quarantine (id TEXT, original_path TEXT, "
                    "quarantined_path TEXT, threat_name TEXT, quarantined_at TEXT)"
                )
                database.execute(
                    "INSERT INTO quarantine VALUES (?, ?, ?, ?, ?)",
                    ("record-1", "/tmp/eicar.com", "/quarantine/eicar.com", "EICAR", "now"),
                )
            with mock.patch.object(MODULE, "QUARANTINE_DB", database_path), \
                 mock.patch.object(MODULE, "THREAT_JOURNALS", ()):
                records = MODULE.prevention_fingerprints()
            self.assertEqual(records["quarantine:record-1"]["target"], "/tmp/eicar.com")

    def test_apple_event_is_preserved_as_stable_rule_evidence(self):
        snapshot = {
            "incidents": [{
                "id": "incident-tcc",
                "state": "new",
                "alert": {
                    "title": "Automation permission granted",
                    "occurrenceCount": 1,
                    "contributingSignals": [{
                        "metadata": {
                            "appleEvent": "tcc-permission-modified",
                            "ruleTier": "review",
                        }
                    }],
                },
            }]
        }
        decoded = MODULE.incident_fingerprints_from_snapshot(snapshot)
        record = next(iter(decoded.values()))
        self.assertEqual(record["reasons"], ["tcc-permission-modified"])
        self.assertEqual(record["tiers"], ["review"])

    def test_matching_incidents_accepts_a_new_grouped_occurrence_only(self):
        before = {"incident:1:new": {
            "reasons": ["credential_store_access"], "tiers": ["review"], "paths": []
        }}
        after = {
            **before,
            "incident:2:new": {
                "reasons": ["credential_store_access"], "tiers": ["review"], "paths": []
            },
        }
        matches = MODULE.matching_incidents(
            before, after, {"credential_store_access"}, {"review"}
        )
        self.assertEqual([identifier for identifier, _ in matches], ["incident:2:new"])

    def test_matching_incidents_can_require_the_exact_fixture_path(self):
        before = {}
        after = {
            "wrong:1:new": {
                "reasons": ["file_integrity_deleted"],
                "tiers": ["review"],
                "paths": ["/Users/example/Library/LaunchAgents/other.plist"],
            },
            "right:1:new": {
                "reasons": ["file_integrity_deleted"],
                "tiers": ["review"],
                "paths": ["/Users/example/Library/LaunchAgents/fixture.plist"],
            },
        }
        matches = MODULE.matching_incidents(
            before,
            after,
            {"file_integrity_deleted"},
            {"review"},
            "/Users/example/Library/LaunchAgents/fixture.plist",
        )
        self.assertEqual([identifier for identifier, _ in matches], ["right:1:new"])

    def test_mapping_review_rejects_an_unrelated_background_occurrence(self):
        lineage = MODULE.FixtureLineage(4100, {4100, 4101})
        lineage.process_groups.add(4100)
        after = {
            "background:1:new": {
                "reasons": ["system_discovery"], "tiers": ["review"],
                "paths": [], "processIDs": [900], "parentPIDs": [1],
                "processGroupIDs": [900], "sessionIDs": [100],
            },
            "fixture:1:new": {
                "reasons": ["system_discovery"], "tiers": ["review"],
                "paths": [], "processIDs": [4101], "parentPIDs": [4100],
                "processGroupIDs": [4100], "sessionIDs": [200],
            },
        }
        matches = MODULE.matching_incidents(
            {}, after, {"system_discovery"}, {"review"}, fixture_lineage=lineage
        )
        self.assertEqual([identifier for identifier, _ in matches], ["fixture:1:new"])

    def test_occurrence_count_increase_is_new_evidence_for_web_canary(self):
        before = {"canary:1:reviewed": {
            "reasons": ["NICK_CANARY_WEB"], "tiers": ["inform"], "paths": [],
        }}
        after = {**before, "canary:2:reviewed": {
            "reasons": ["NICK_CANARY_WEB"], "tiers": ["inform"], "paths": [],
        }}
        matches = MODULE.matching_incidents(
            before, after, {"NICK_CANARY_WEB"}, {"inform"}
        )
        self.assertEqual([identifier for identifier, _ in matches], ["canary:2:reviewed"])

    def test_login_item_requires_the_fixture_unique_identifier(self):
        after = {
            "unrelated:1:new": {
                "reasons": ["background-item-added"], "tiers": ["review"],
                "paths": [], "correlationValues": ["com.example.other"],
            },
            "fixture:1:new": {
                "reasons": ["background-item-added"], "tiers": ["review"],
                "paths": [],
                "correlationValues": ["com.3nsofts.nick.scorecard.loginitem.123"],
            },
        }
        matches = MODULE.matching_incidents(
            {}, after, {"background-item-added"}, {"review"},
            expected_correlation_value="com.3nsofts.nick.scorecard.loginitem.123",
        )
        self.assertEqual([identifier for identifier, _ in matches], ["fixture:1:new"])

    def test_login_item_matches_exact_randomized_fixture_app_path(self):
        fixture_path = "/tmp/nick-scorecard-abc123/Nick Login Item Fixture.app"
        after = {
            "unrelated:1:new": {
                "reasons": ["background-item-added"], "tiers": ["review"],
                "paths": ["/Applications/Unrelated.app"],
            },
            "fixture:1:new": {
                "reasons": ["background-item-added"], "tiers": ["review"],
                "paths": [fixture_path],
                "processIDs": [86148],
            },
        }
        matches = MODULE.matching_incidents(
            {}, after, {"background-item-added"}, {"review"},
            expected_path=fixture_path,
        )
        self.assertEqual([identifier for identifier, _ in matches], ["fixture:1:new"])

    def test_btm_persistence_path_is_normalized_as_path_evidence(self):
        fixture_path = "/tmp/nick-scorecard-a95bgdfz/Nick Login Item Fixture.app"
        persisted_path = os.path.realpath(fixture_path)
        snapshot = {"incidents": [{
            "id": "btm-fixture", "state": "new",
            "alert": {"occurrenceCount": 1, "contributingSignals": [{
                "metadata": {
                    "rule": "background-item-added",
                    "ruleTier": "review",
                    "persistencePath": persisted_path,
                    "launchItemLabel": "Nick Login Item Fixture",
                }
            }]},
        }]}
        record = next(iter(MODULE.incident_fingerprints_from_snapshot(snapshot).values()))
        self.assertEqual(record["paths"], [persisted_path])
        matches = MODULE.matching_incidents(
            {}, {"fixture:1:new": record},
            {"background-item-added"}, {"review"},
            expected_path=fixture_path,
        )
        self.assertEqual([identifier for identifier, _ in matches], ["fixture:1:new"])

    def test_network_canary_still_requires_fixture_process_lineage(self):
        lineage = MODULE.FixtureLineage(4200, {4200, 4201})
        after = {
            "unrelated:1:new": {
                "reasons": ["NICK_CANARY_WEB", "nick_test_indicator"],
                "tiers": ["inform"], "paths": [], "processIDs": [9000],
                "parentPIDs": [], "processGroupIDs": [], "sessionIDs": [],
            },
            "fixture:1:new": {
                "reasons": ["NICK_CANARY_WEB", "nick_test_indicator"],
                "tiers": ["inform"], "paths": [], "processIDs": [4201],
                "parentPIDs": [], "processGroupIDs": [], "sessionIDs": [],
            },
        }
        matches = MODULE.matching_incidents(
            {}, after, {"NICK_CANARY_WEB", "nick_test_indicator"}, {"inform"},
            fixture_lineage=lineage,
        )
        self.assertEqual([identifier for identifier, _ in matches], ["fixture:1:new"])

    def test_fingerprint_preserves_async_correlation_and_network_pid(self):
        snapshot = {"incidents": [{
            "id": "async-evidence", "state": "new",
            "alert": {"title": "test", "occurrenceCount": 1, "contributingSignals": [{
                "metadata": {
                    "rule": "NICK_CANARY_WEB", "ruleTier": "inform",
                    "indicatorID": "NICK_CANARY_WEB", "pid": "4242",
                    "launchItemLabel": "com.3nsofts.fixture",
                }
            }]},
        }]}
        record = next(iter(MODULE.incident_fingerprints_from_snapshot(snapshot).values()))
        self.assertEqual(record["processIDs"], [4242])
        self.assertEqual(
            record["correlationValues"],
            ["NICK_CANARY_WEB", "com.3nsofts.fixture"],
        )

    def test_strict_wait_does_not_stop_at_detection_before_durable_denial(self):
        detected = {"rename:1:new": {"reasons": ["mass_file_rename"], "tiers": ["protected"], "paths": ["/tmp/fixture"]}}
        denied = {"rename:2:new": {"reasons": ["mass_file_rename"], "tiers": ["protected"], "paths": ["/tmp/fixture"], "endpointDenied": True}}
        with mock.patch.object(MODULE, "load_incident_fingerprints", side_effect=[detected, denied]), \
             mock.patch.object(MODULE, "prevention_fingerprints", return_value={}), \
             mock.patch.object(MODULE.time, "sleep"):
            after, matches = MODULE.wait_for_matching_incidents({}, {"mass_file_rename"}, {"protected"},
                timeout=1, poll_interval=0, require_prevention=True, prevention_before={})
        self.assertEqual(after, denied)
        self.assertTrue(matches[0][1]["endpointDenied"])

    def test_wait_polls_until_delayed_expected_evidence_arrives(self):
        before = {"old:1:new": {"reasons": ["process_discovery"], "tiers": ["review"]}}
        unrelated = {
            **before,
            "late-prior-row:1:new": {"reasons": ["credential_store_access"], "tiers": ["review"]},
        }
        expected = {
            **unrelated,
            "tcc:1:new": {"reasons": ["tcc-permission-modified"], "tiers": ["review"]},
        }
        with mock.patch.object(
            MODULE, "load_incident_fingerprints", side_effect=[unrelated, expected]
        ), mock.patch.object(MODULE.time, "sleep"):
            after, matches = MODULE.wait_for_matching_incidents(
                before,
                {"tcc-permission-modified"},
                {"review"},
                timeout=1,
                poll_interval=0,
            )
        self.assertEqual(after, expected)
        self.assertEqual([identifier for identifier, _ in matches], ["tcc:1:new"])


class FixtureInvocationTests(unittest.TestCase):
    def test_gatekeeper_fixture_builds_only_an_inert_quarantined_scratch_app(self):
        fixture = (MODULE.ROOT / "Scripts/fixtures/gatekeeper-user-override.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("NICK_FIXTURE_ROOT", fixture)
        self.assertIn("osacompile", fixture)
        self.assertIn("com.apple.quarantine", fixture)
        self.assertIn("lsregister", fixture)
        self.assertIn("date +%s", fixture)
        self.assertIn("spctl --assess", fixture)
        self.assertNotIn("00000000", fixture)
        self.assertIn("Do NOT choose Move to Trash", fixture)
        self.assertIn("x-apple.systempreferences:com.apple.preference.security?General", fixture)
        self.assertIn("on run", fixture)
        self.assertIn("quit", fixture)
        self.assertNotIn("curl", fixture)
        self.assertNotIn("http", fixture)

    def test_gui_privacy_fixtures_run_in_the_console_users_launchd_session(self):
        self.assertIn("gatekeeper-user-override", MODULE.INTERACTIVE_FIXTURES)
        self.assertIn("tcc-modification", MODULE.INTERACTIVE_FIXTURES)

    def test_tcc_fixture_registers_its_bundle_before_targeted_reset(self):
        fixture = (MODULE.ROOT / "Scripts/fixtures/tcc-modification.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("lsregister", fixture)
        self.assertIn("NSAppleEventsUsageDescription", fixture)
        self.assertIn("NICK_FIXTURE_HOME", fixture)
        self.assertIn("Applications/Nick Scorecard Fixtures", fixture)
        self.assertIn("trap cleanup", fixture)
        self.assertIn('display dialog "Nick TCC fixture completed."', fixture)
        self.assertIn("If an Apple Events prompt appears", fixture)
        self.assertNotIn('root="${NICK_FIXTURE_ROOT', fixture)
        self.assertLess(fixture.index('"$lsregister" -f "$app"'), fixture.index("tccutil reset"))

    def test_browser_store_fixture_uses_an_ad_hoc_helper_not_an_apple_reader(self):
        fixture = (MODULE.ROOT / "Scripts/fixtures/browser-store-read.sh").read_text(
            encoding="utf-8"
        )
        helper = MODULE.ROOT / "Scripts/fixtures/helpers/credential-store-reader.c"

        self.assertIn("NICK_FIXTURE_ROOT", fixture)
        self.assertIn("xcrun clang", fixture)
        self.assertNotIn("/bin/cat", fixture)
        self.assertTrue(helper.is_file())

    def test_web_protocol_row_uses_only_the_signed_harmless_canary(self):
        reasons, tiers = MODULE.EXPECTED["T1071.001"]
        self.assertIn("NICK_CANARY_WEB", reasons)
        self.assertEqual(tiers, {"inform"})

        fixture = (
            ROOT / "Scripts" / "fixtures" / "known-dangerous-destination.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("canary-web.sh", fixture)
        self.assertNotIn("evil", fixture.lower())

    def test_sudo_uid_fixture_receives_owned_scratch_and_explicit_root(self):
        fixture = ROOT / "Scripts" / "fixtures" / "permission-modification.sh"
        with tempfile.TemporaryDirectory(prefix="nick-scorecard-test-") as scratch:
            with mock.patch.object(MODULE.os, "chown") as chown:
                MODULE.prepare_fixture_scratch(scratch, 501, 20)
            chown.assert_called_once_with(scratch, 501, 20)
            self.assertEqual(os.stat(scratch).st_mode & 0o777, 0o700)

            fixture_user = pwd.getpwuid(os.getuid())
            command = MODULE.user_fixture_command(fixture, scratch, fixture_user.pw_name)
            self.assertEqual(command, [
                "/usr/bin/sudo", "-H", "-u", fixture_user.pw_name, "--", "/usr/bin/env",
                f"NICK_FIXTURE_ROOT={scratch}",
                f"NICK_FIXTURE_USER={fixture_user.pw_name}",
                f"NICK_FIXTURE_HOME={fixture_user.pw_dir}",
                str(fixture),
            ])

            # Exercise the actual fixture with the exact env segment passed
            # after sudo. This catches both a missing env assignment and an
            # unusable root-created scratch directory without requiring CI sudo.
            env_index = command.index("/usr/bin/env")
            completed = subprocess.run(
                command[env_index:], check=False, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout)

    def test_login_item_runs_in_the_console_launchd_session(self):
        fixture = ROOT / "Scripts" / "fixtures" / "login-item-add.sh"
        user = pwd.getpwuid(os.getuid()).pw_name
        command = MODULE.console_user_fixture_command(fixture, "/tmp/fixture", user, 501)
        self.assertEqual(command[:3], ["/bin/launchctl", "asuser", "501"])
        self.assertEqual(command[3:8], ["/usr/bin/sudo", "-H", "-u", user, "--"])
        fixture_text = fixture.read_text(encoding="utf-8")
        self.assertIn("NICK_FIXTURE_LOGIN_ITEM=", fixture_text)


class CorpusAndStrictModeTests(unittest.TestCase):
    def test_external_hash_manifest_replays_hashes_without_samples(self):
        with tempfile.TemporaryDirectory(prefix="nick-hash-replay-") as directory:
            root = Path(directory)
            first = "a" * 64
            second = "b" * 64
            manifest = root / "independent.json"
            manifest.write_text(json.dumps({
                "source": "independent licensed corpus",
                "samples": [{"sha256": first}, {"sha256": second}],
            }), encoding="utf-8")
            database = root / "signatures.db"
            with sqlite3.connect(database) as connection:
                connection.execute("CREATE TABLE signatures (hash TEXT PRIMARY KEY)")
                connection.execute("INSERT INTO signatures VALUES (?)", (first,))
            result = MODULE.replay_hash_manifest(manifest, database)
        self.assertEqual(result["total"], "2")
        self.assertEqual(result["alerted"], "1")
        self.assertEqual(result["percentage"], "50.00%")

    def test_eset_manifest_is_refused_as_measurement_set(self):
        with tempfile.TemporaryDirectory(prefix="nick-hash-replay-") as directory:
            manifest = Path(directory) / "manifest.json"
            manifest.write_text(json.dumps({
                "source": "ESET research set", "hashes": ["a" * 64],
            }), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "not an independent"):
                MODULE.manifest_hashes(manifest, manifest.read_bytes())

    def test_progress_writer_replaces_root_owned_output_with_invoking_user_owner(self):
        with tempfile.TemporaryDirectory(prefix="nick-progress-writer-") as directory:
            progress = Path(directory) / "progress.md"
            progress.write_text("old", encoding="utf-8")
            with mock.patch.object(MODULE, "PROGRESS_DOC", progress), \
                 mock.patch.object(MODULE.os, "geteuid", return_value=0), \
                 mock.patch.dict(MODULE.os.environ, {"SUDO_UID": "501", "SUDO_GID": "20"}), \
                 mock.patch.object(MODULE.os, "chown") as chown:
                MODULE.write_progress_document("new")
            self.assertEqual(progress.read_text(encoding="utf-8"), "new")
            chown.assert_called_once()
            self.assertEqual(chown.call_args.args[1:], (501, 20))

    def test_progress_heading_describes_cumulative_evidence(self):
        techniques = [{"id": "T1", "name": "One"}]
        with tempfile.TemporaryDirectory(prefix="nick-progress-heading-") as directory:
            progress = Path(directory) / "progress.md"
            with mock.patch.object(MODULE, "PROGRESS_DOC", progress):
                MODULE.update_progress(techniques, {})
            rendered = progress.read_text(encoding="utf-8")
        self.assertIn(
            f"cumulative evidence through build {MODULE.EXPECTED_BUILD}", rendered
        )

    def test_strict_mode_reads_authenticated_settings_payload(self):
        payload = base64.b64encode(json.dumps({
            "strictModeEnabled": True, "blockingKillSwitch": False,
        }).encode()).decode()
        with tempfile.TemporaryDirectory(prefix="nick-strict-") as directory:
            settings = Path(directory) / "settings.json"
            settings.write_text(json.dumps({"payload": payload}), encoding="utf-8")
            self.assertEqual(MODULE.strict_mode_configuration(settings), (True, False))

    def test_scorecard_keeps_the_attack_denominator_at_24(self):
        techniques = [{"id": f"T{index}", "name": str(index)} for index in range(24)]
        rows = MODULE.full_scorecard_rows(techniques, {})
        attack = next(row for row in rows if "ATT&CK for macOS" in row)
        self.assertIn("0/24 alerted", attack)
        self.assertIn("0/24 prevented", attack)

    def test_scorecard_keeps_known_family_corpus_metrics_deferred(self):
        techniques = [{"id": f"T{index}", "name": str(index)} for index in range(24)]
        rendered = "\n".join(MODULE.full_scorecard_rows(techniques, {}))
        self.assertIn("Known families", rendered)
        self.assertIn("hash/signature", rendered)
        self.assertIn("not measured", rendered)

    def test_scorecard_uses_current_expected_build_for_unmeasured_runtime_rows(self):
        techniques = [{"id": f"T{index}", "name": str(index)} for index in range(24)]
        rows = MODULE.full_scorecard_rows(techniques, {})
        false_positive = next(row for row in rows if "False positives" in row)
        health = next(row for row in rows if "ES health" in row)
        self.assertIn(f"build {MODULE.EXPECTED_BUILD}", false_positive)
        self.assertIn(f"build {MODULE.EXPECTED_BUILD}", health)

    def test_scorecard_preserves_build_5084_continuity_evidence(self):
        techniques = [{"id": f"T{index}", "name": str(index)} for index in range(24)]
        rows = MODULE.full_scorecard_rows(techniques, {})
        app_alive = next(row for row in rows if "extension stopped, app alive" in row)
        both_gone = next(row for row in rows if "extension and app both gone" in row)
        self.assertIn("| PASS |", app_alive)
        self.assertIn("D33C26DD-4F34-40D3-A78D-1490454C12D7:1:new", app_alive)
        self.assertIn("| PASS |", both_gone)
        self.assertIn("actual extension gap was ~1 s", both_gone)

    def test_scorecard_does_not_hide_missing_mandatory_rows(self):
        techniques = json.loads(MODULE.MANIFEST.read_text(encoding="utf-8"))["techniques"]
        results = {
            item["id"]: {"status": "PASS", "evidence": f"evidence-{item['id']}"}
            for item in techniques if item["id"] != "T1562.001"
        }
        attack = next(
            row for row in MODULE.full_scorecard_rows(techniques, results)
            if "ATT&CK for macOS" in row
        )
        self.assertIn("mandatory incomplete", attack)
        self.assertIn("tampering with Nick: T1562.001 not measured", attack)

    def test_scorecard_reports_mandatory_complete_only_with_all_rows(self):
        techniques = json.loads(MODULE.MANIFEST.read_text(encoding="utf-8"))["techniques"]
        results = {
            item["id"]: {"status": "PASS", "evidence": f"evidence-{item['id']}"}
            for item in techniques
        }
        attack = next(
            row for row in MODULE.full_scorecard_rows(techniques, results)
            if "ATT&CK for macOS" in row
        )
        self.assertIn("all mandatory rows alerted", attack)


class InstalledBuildTests(unittest.TestCase):
    EXTENSION_OUTPUT = f"""
--- com.apple.system_extension.network_extension
* * UXGW5V3BY6 com.ehsanazish.nick.NickNetFilter (5.1.0/{MODULE.EXPECTED_BUILD}) NickNetFilter [activated enabled]
--- com.apple.system_extension.endpoint_security
* * UXGW5V3BY6 com.ehsanazish.nick.NickExtension (5.1.0/{MODULE.EXPECTED_BUILD}) NickExtension [activated enabled]
"""

    def test_active_extension_builds_reads_both_active_components(self):
        self.assertEqual(MODULE.active_extension_builds(self.EXTENSION_OUTPUT), {
            "com.ehsanazish.nick.NickExtension": MODULE.EXPECTED_BUILD,
            "com.ehsanazish.nick.NickNetFilter": MODULE.EXPECTED_BUILD,
        })

    def test_installed_build_header_accepts_exact_expected_build(self):
        with tempfile.TemporaryDirectory(prefix="nick-build-header-") as directory:
            info = Path(directory) / "Info.plist"
            with info.open("wb") as stream:
                plistlib.dump({"CFBundleVersion": MODULE.EXPECTED_BUILD}, stream)
            completed = subprocess.CompletedProcess([], 0, self.EXTENSION_OUTPUT, "")
            with mock.patch.object(MODULE.subprocess, "run", return_value=completed):
                app, extensions = MODULE.installed_build_header(info, Path("/usr/bin/systemextensionsctl"))
        self.assertEqual(app, MODULE.EXPECTED_BUILD)
        self.assertEqual(set(extensions), set(MODULE.EXPECTED_EXTENSIONS))

    def test_installed_build_header_refuses_any_component_mismatch(self):
        output = self.EXTENSION_OUTPUT.replace(f"NickNetFilter (5.1.0/{MODULE.EXPECTED_BUILD})",
                                               "NickNetFilter (5.1.0/5068)")
        with tempfile.TemporaryDirectory(prefix="nick-build-header-") as directory:
            info = Path(directory) / "Info.plist"
            with info.open("wb") as stream:
                plistlib.dump({"CFBundleVersion": MODULE.EXPECTED_BUILD}, stream)
            completed = subprocess.CompletedProcess([], 0, output, "")
            with mock.patch.object(MODULE.subprocess, "run", return_value=completed), \
                 self.assertRaisesRegex(RuntimeError, "NickNetFilter=5068"):
                MODULE.installed_build_header(info, Path("/usr/bin/systemextensionsctl"))

    def test_login_item_and_tcc_rows_accept_the_persisted_policy_evidence(self):
        self.assertEqual(MODULE.EXPECTED["T1547.015"], ({"background-item-added"}, {"review"}))
        self.assertEqual(
            MODULE.EXPECTED["T1548.006"],
            ({"tcc-permission-modified"}, {"review", "observed"}),
        )

    def test_file_deletion_uses_inert_baselined_fixture(self):
        manifest = json.loads(MODULE.MANIFEST.read_text(encoding="utf-8"))
        row = next(item for item in manifest["techniques"] if item["id"] == "T1070.004")
        self.assertEqual(row["fixture"], "file-deletion")
        self.assertIn("file_integrity_deleted", MODULE.EXPECTED["T1070.004"][0])
        self.assertIn("T1070.004", MODULE.DETECTION_ONLY_TECHNIQUES)
        self.assertNotIn("file-deletion", MODULE.ROOT_FIXTURES)

    def test_detected_rows_are_complete_for_failed_reruns(self):
        self.assertIn("DETECTED", MODULE.COMPLETED_STATUSES)

    def test_file_deletion_waits_for_recorder_phase_then_cleans_up(self):
        fixture = MODULE.ROOT / "Scripts" / "fixtures" / "file-deletion.sh"
        with tempfile.TemporaryDirectory(prefix="nick-delete-fixture-") as directory:
            root = Path(directory)
            home = root / "home"
            launch_agents = home / "Library" / "LaunchAgents"
            target = launch_agents / "com.ehsanazish.nick.fixture.deletion.plist"
            scratch = root / "scratch"
            scratch.mkdir()
            marker = scratch / "file-deletion-phase2"
            environment = os.environ.copy()
            environment.update({
                "NICK_FIXTURE_HOME": str(home),
                "NICK_FIXTURE_ROOT": str(scratch),
                "NICK_FIXTURE_USER": pwd.getpwuid(os.getuid()).pw_name,
                "SUDO_USER": "root",
            })
            process = subprocess.Popen(
                [str(fixture)], env=environment, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
            deadline = time.monotonic() + 5
            while not target.exists() and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertTrue(target.exists(), "fixture did not create the inert plist")
            self.assertTrue(launch_agents.is_dir(), "user fixture did not create LaunchAgents")
            marker.touch()
            output, _ = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, output)
            self.assertFalse(target.exists(), "cleanup trap left the fixture behind")

    def test_file_deletion_two_phase_recorder_reports_detected_and_reminds(self):
        created = ({"created:1:new": {
            "reasons": ["file_integrity_created"],
            "tiers": ["review"],
            "paths": ["/Users/fixture/Library/LaunchAgents/com.ehsanazish.nick.fixture.deletion.plist"],
        }}, [("created:1:new", {
            "reasons": ["file_integrity_created"], "tiers": ["review"]
        })])
        deleted = ({}, [("deleted:1:new", {
            "reasons": ["file_integrity_deleted"], "tiers": ["review"]
        })])
        process = mock.Mock()
        process.communicate.return_value = ("", None)
        process.poll.return_value = 0
        user = mock.Mock(pw_dir="/Users/fixture")
        with tempfile.TemporaryDirectory(prefix="nick-delete-recorder-") as scratch, \
             mock.patch.object(MODULE.pwd, "getpwnam", return_value=user), \
             mock.patch.object(MODULE.subprocess, "Popen", return_value=process), \
             mock.patch.object(MODULE, "wait_for_matching_incidents", side_effect=[created, deleted]), \
             mock.patch("builtins.print") as output:
            result = MODULE.run_file_deletion_replay(
                Path("/fixtures/file-deletion.sh"), scratch, "fixture", {}, time.time()
            )
        self.assertEqual(result["status"], "DETECTED")
        self.assertIn("created=created:1:new", result["evidence"])
        self.assertIn("deleted=deleted:1:new", result["evidence"])
        self.assertTrue(any("remain pending" in str(call) for call in output.call_args_list))

    def test_file_deletion_creation_timeout_still_releases_fixture_cleanup(self):
        process = mock.Mock()
        process.communicate.return_value = ("", None)
        process.poll.return_value = 0
        user = mock.Mock(pw_dir="/Users/fixture")
        with tempfile.TemporaryDirectory(prefix="nick-delete-recorder-") as scratch, \
             mock.patch.object(MODULE.pwd, "getpwnam", return_value=user), \
             mock.patch.object(MODULE.subprocess, "Popen", return_value=process), \
             mock.patch.object(MODULE, "wait_for_matching_incidents", return_value=({}, [])), \
             mock.patch("builtins.print"):
            result = MODULE.run_file_deletion_replay(
                Path("/fixtures/file-deletion.sh"), scratch, "fixture", {}, time.time()
            )
            self.assertTrue((Path(scratch) / "file-deletion-phase2").exists())
        self.assertEqual(result, {"status": "FAIL", "evidence": "creation not detected"})


class PreviousResultsTests(unittest.TestCase):
    def test_incomplete_rerun_does_not_erase_completed_cumulative_evidence(self):
        previous = {
            "T1070.004": {"status": "DETECTED", "evidence": "incident=old"},
            "T1555.003": {"status": "RAN: NO EVIDENCE", "evidence": "old miss"},
        }
        current = {
            "T1070.004": {"status": "FAIL", "evidence": "prior pending state"},
            "T1555.003": {"status": "PASS", "evidence": "incident=new"},
        }

        merged = MODULE.retain_completed_results(previous, current)

        self.assertEqual(merged["T1070.004"], previous["T1070.004"])
        self.assertEqual(merged["T1555.003"], current["T1555.003"])

    def test_prevention_upgrades_prior_detection(self):
        previous = {"T1204.002": {"status": "PASS", "evidence": "detected"}}
        current = {"T1204.002": {"status": "PREVENTED", "evidence": "quarantined"}}

        self.assertEqual(
            MODULE.retain_completed_results(previous, current)["T1204.002"],
            current["T1204.002"],
        )

    def test_previous_results_parses_status_and_escaped_evidence_pipe(self):
        content = "\n".join([
            "| ID | Technique | Result | Evidence |",
            "|---|---|---|---|",
            r"| T1071.001 | Web Protocols | PASS | rule=NICK\|CANARY; tier=inform |",
            "| T1547 | Boot Persistence | PREVENTED | incident=ABC123 |",
        ])
        with tempfile.TemporaryDirectory(prefix="nick-previous-results-") as directory:
            progress = Path(directory) / "progress.md"
            progress.write_text(content, encoding="utf-8")
            with mock.patch.object(MODULE, "PROGRESS_DOC", progress):
                results = MODULE.previous_results()

        self.assertEqual(results["T1071.001"], {
            "status": "PASS",
            "evidence": "rule=NICK|CANARY; tier=inform",
        })
        self.assertEqual(results["T1547"]["status"], "PREVENTED")

    def test_previous_results_ignores_malformed_rows_in_linear_time(self):
        long_malformed_row = "| T1027 | " + ("evidence " * 20_000)
        with tempfile.TemporaryDirectory(prefix="nick-previous-results-") as directory:
            progress = Path(directory) / "progress.md"
            progress.write_text(long_malformed_row, encoding="utf-8")
            with mock.patch.object(MODULE, "PROGRESS_DOC", progress):
                self.assertEqual(MODULE.previous_results(), {})


if __name__ == "__main__":
    unittest.main()
