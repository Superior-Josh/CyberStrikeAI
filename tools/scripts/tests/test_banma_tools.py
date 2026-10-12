"""Offline fixtures; none of these files or verdicts represent target tests."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import sys

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("case_tool", ROOT / "tools/scripts/banma_pentest_run_cases.py")
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
sys.modules["banma_pentest_run_cases"] = tool
report_spec = importlib.util.spec_from_file_location("report_tool", ROOT / "tools/scripts/banma_report.py")
report = importlib.util.module_from_spec(report_spec)
report_spec.loader.exec_module(report)
sys.modules["banma_report"] = report


class CaseTests(unittest.TestCase):
    def test_spaced_default_credentials_are_redacted(self):
        value = tool.redact("默认凭据 admin // password； root : letmein")
        self.assertNotIn("password", value)
        self.assertNotIn("letmein", value)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.original_root = tool.ROOT
        self.addCleanup(setattr, tool, "ROOT", self.original_root)
        tool.ROOT = Path(self.temp.name)
        self.context, self.cases = tool.catalog(ROOT / "cases")
        self.created = tool.init_run(self.cases, self.context, {"test_name": "offline-fixture", "test_info": {"targets": ["OFFLINE-NO-TARGET"], "source": "offline fixture", "write_authorized": False}})
        self.run = Path(self.created["run_dir"])
        self.source = tool.ROOT / "native.txt"
        self.source.write_text("OFFLINE FIXTURE ONLY\nNORMAL/VARIANT\n")

    def payload(self, result="通过"):
        value = {
            "scope_items": [{"item_id": "S1", "requirement_ref": "required", "must_complete": True, "applicability_reason": "fixture", "baseline_source": "fixture", "planned_checks": ["fixture"]}],
            "actual_steps": [{"operation_id": "O1", "item_ids": ["S1"], "tool_name": "offline-fixture", "method_summary": "fixture", "tool_status": "completed", "execution_id": "00000000-0000-4000-8000-000000000001"}],
            "observations": [{"observation_id": "V1", "operation_id": "O1", "summary": "fixture", "evidence_ids": ["E1"]}],
            "evidence": [{"evidence_id": "E1", "source_type": "原始文件", "source_ref": "00000000-0000-4000-8000-000000000001", "coverage": "fixture only", "source_path": str(self.source), "provenance": {"execution_id": "00000000-0000-4000-8000-000000000001", "tool_name": "offline-fixture", "sha256": tool.digest(self.source.read_bytes()) if self.source.exists() else "missing"}}],
            "item_results": [{"item_id": "S1", "result": result, "reason": "fixture", "observation_ids": ["V1"], "evidence_ids": ["E1"]}],
            "judgment_review": {"approved": True, "basis": "OFFLINE FIXTURE ONLY"},
            "result": result, "judgment_reason": "OFFLINE FORMAT TEST", "coverage_limitations": ["NO TARGET TEST"],
            "recovery": {"status": "未涉及", "evidence_ids": [], "actual_actions": [], "remaining_changes": []},
        }
        if result == "中断":
            value.update(interruption_reason="offline fixture environment unavailable", interruption_kind="环境问题")
        return value

    def save(self, payload):
        return tool.save_result(self.run, "PT_WEB_01", self.cases["PT_WEB_01"], payload)

    def check_completion(self):
        return tool.completion_check(str(self.run), str(ROOT / "cases"))

    def test_load_machine_budget_rejects_conflict_with_original_steps(self):
        directory = tool.ROOT / "machine-cases"
        import shutil
        shutil.copytree(ROOT / "cases", directory)
        path = directory / "anonymous/PT_WEB_11.yaml"
        value = tool.yaml.safe_load(path.read_text())
        value["load_budget"]["baseline_requests"] = 4
        path.write_text(tool.yaml.safe_dump(value, allow_unicode=True, sort_keys=False))
        with self.assertRaises(tool.ToolError) as raised:
            tool.catalog(directory)
        self.assertEqual(raised.exception.code, "CASE_CONFIG_ERROR")

    def test_execution_order_preserves_scope_and_report_order(self):
        numbered = list(self.cases)
        order = self.context["execution_order"]
        self.assertEqual(len(order), 44)
        self.assertEqual(set(order), set(numbered))
        self.assertEqual(numbered[0], "PT_WEB_01")
        self.assertEqual(numbered[18], "PT_WEB_AUTH_01")
        self.assertEqual(order[0], "PT_WEB_04")
        self.assertEqual(order[-1], "PT_WEB_11")
        for before, after in [("PT_WEB_08", "PT_WEB_06"),
                              ("PT_WEB_09", "PT_WEB_06"),
                              ("PT_WEB_AUTH_18", "PT_WEB_AUTH_07"),
                              ("PT_WEB_AUTH_23", "PT_WEB_01")]:
            self.assertLess(order.index(before), order.index(after))
        self.assertEqual(self.created["execution_order"], order)
        listing = tool.dispatch("list", str(ROOT / "cases"), str(self.run))
        self.assertEqual(listing["selected_case_ids"], numbered)
        self.assertEqual(listing["pending"], order)
        self.assertEqual([c["id"] for c in listing["cases"]], order)
        checked = self.check_completion()
        self.assertEqual(checked["catalog_case_ids"], numbered)
        self.assertEqual(checked["selected_case_ids"], numbered)
        self.assertEqual(checked["pending_case_ids"], order)
        selected = ["PT_WEB_11", "PT_WEB_01", "PT_WEB_04"]
        created = tool.init_run(self.cases, self.context, {
            "test_name": "offline-subset-order",
            "test_info": {"targets": ["OFFLINE-NO-TARGET"], "case_ids": selected},
        })
        listing = tool.dispatch("list", str(ROOT / "cases"), created["run_dir"])
        self.assertEqual(listing["selected_case_ids"], selected)
        self.assertEqual(listing["pending"], ["PT_WEB_04", "PT_WEB_01", "PT_WEB_11"])
        tool.dispatch("show", str(ROOT / "cases"), created["run_dir"], "PT_WEB_04")
        tool.save_result(Path(created["run_dir"]), "PT_WEB_04", self.cases["PT_WEB_04"], self.payload())
        checked = tool.completion_check(created["run_dir"], str(ROOT / "cases"))
        self.assertEqual(checked["selected_case_ids"], selected)
        self.assertEqual(checked["pending_case_ids"], ["PT_WEB_01", "PT_WEB_11"])
        built = self.build()
        content = Path(built["report_path"]).read_text()
        headings = [line.split()[2] for line in content.splitlines()
                    if line.startswith("#### ") and " PT_WEB_" in line]
        self.assertEqual(headings, numbered)

    def test_execution_order_rejects_missing_duplicate_and_unknown_ids(self):
        order = self.context["execution_order"]
        for invalid in [order[:-1], order + [order[0]], order[:-1] + ["PT_WEB_99"],
                        order[:-1] + [None]]:
            with self.assertRaises(tool.ToolError) as raised:
                tool.execution_order(dict(self.context, execution_order=invalid), self.cases)
            self.assertEqual(raised.exception.code, "CASE_CONFIG_ERROR")

    def test_completion_full_partial_and_read_only(self):
        self.assertEqual(len(self.check_completion()["pending_case_ids"]), 44)
        for cid, case in self.cases.items():
            tool.dispatch("show", str(ROOT / "cases"), str(self.run), cid)
            tool.save_result(self.run, cid, case, self.payload())
        before = {str(p): p.read_bytes() for p in self.run.rglob("*") if p.is_file()}
        self.source.unlink()  # Check saved copies only; no original target file reads.
        checked = self.check_completion()
        self.assertEqual(checked["valid_saved_count"], 44)
        self.assertEqual(checked["pending_case_ids"], [])
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.run.rglob("*") if p.is_file()})
        path = self.run / "evidence/PT_WEB_AUTH_26.json"
        path.unlink()
        self.assertEqual(self.check_completion()["pending_case_ids"], ["PT_WEB_AUTH_26"])

    def test_completion_respects_selected_scope_and_rejects_corrupt_records(self):
        meta_path = self.run / "evidence/test_info.json"
        meta = tool.read_json(meta_path)
        meta["test_info"]["case_ids"] = ["PT_WEB_01"]
        meta_path.write_text(json.dumps(meta))
        tool.dispatch("show", str(ROOT / "cases"), str(self.run), "PT_WEB_01")
        self.save(self.payload())
        self.assertEqual(self.check_completion()["pending_case_ids"], [])
        path = self.run / "evidence/PT_WEB_01.json"
        valid = tool.read_json(path)
        for changed in [dict(valid, observations=[]), dict(valid, case_id="PT_WEB_02"), dict(valid, result="通过", item_results=[])]:
            path.write_text(json.dumps(changed))
            self.assertEqual(self.check_completion()["pending_case_ids"], ["PT_WEB_01"])
        path.write_text(json.dumps(valid))
        source = Path(valid["evidence"][0]["saved_path"])
        source.write_text("CORRUPTED OFFLINE FIXTURE")
        self.assertEqual(self.check_completion()["pending_case_ids"], ["PT_WEB_01"])

    def test_new_contract_requires_provenance_without_second_model(self):
        value = self.payload()
        value["evidence"][0].pop("provenance")
        with self.assertRaises(tool.ToolError) as raised:
            self.save(value)
        self.assertEqual(raised.exception.code, "PROVENANCE_MISMATCH")
        value = self.payload()
        value.pop("judgment_review")
        self.assertEqual(self.save(value)["result"], "通过")

    def test_report_receipt_becomes_pending_after_results_change(self):
        tool.dispatch("show", str(ROOT / "cases"), str(self.run), "PT_WEB_01")
        self.save(self.payload())
        built = self.build()
        report.dispatch("check", str(self.run), str(ROOT / "cases"), str(ROOT / "templates/pentest_report_template.md"), report_file=built["report_path"])
        self.assertFalse(self.check_completion()["report_pending"])
        updated = self.payload()
        updated["judgment_reason"] = "UPDATED OFFLINE OBSERVATION"
        self.save(updated)
        self.assertTrue(self.check_completion()["report_pending"])

    def test_review_input_decodes_native_body_without_secret_values(self):
        import base64
        body = "<input name='user_token' value='PRIVATE_CSRF_MARKER'>"
        capture = {"source": "http-framework-test native response capture", "request_body_base64": base64.b64encode(b"password=PRIVATE_PASSWORD_MARKER&user_token=PRIVATE_CSRF_MARKER").decode(), "body_base64": base64.b64encode(body.encode()).decode(), "request_headers": [["Cookie", "PHPSESSID=PRIVATE_SESSION_MARKER"]], "headers": [["Set-Cookie", "PHPSESSID=PRIVATE_SESSION_MARKER"]]}
        self.source.write_text(json.dumps(capture))
        material = tool.review_input(str(self.run), "PT_WEB_01", self.payload(), str(ROOT / "cases"))
        rendered = json.dumps(material)
        self.assertNotIn("PRIVATE_PASSWORD_MARKER", rendered)
        self.assertNotIn("PRIVATE_CSRF_MARKER", rendered)
        self.assertNotIn("PRIVATE_SESSION_MARKER", rendered)
        self.assertIn("response_csrf_fingerprints", rendered)

    def test_catalog_and_complete_guidance(self):
        self.assertEqual(len(self.cases), 44)
        guide = tool.dispatch("show", str(ROOT / "cases"), str(self.run), "PT_WEB_01")
        self.assertEqual(guide["context"], self.context)
        self.assertEqual(guide["case"], self.cases["PT_WEB_01"])
        contract = guide["save_contract"]
        self.assertIn("item_ids", contract["actual_step_required"])
        self.assertIn("evidence_ids", contract["observation_required"])
        self.assertEqual(set(contract["result_values"]), tool.RESULTS)
        self.assertEqual(contract["interruption_kind_values"], ["环境问题"])
        self.assertIs(guide["execution_scope"]["write_authorized"], False)
        self.assertIn("current_time_utc", guide)
        persisted = tool.read_json(Path(guide["guidance_path"]))
        self.assertEqual(persisted["case"], guide["case"])
        self.assertEqual(persisted["context"], guide["context"])
        self.assertEqual(Path(guide["guidance_path"]).stat().st_mode & 0o777, 0o600)

    def test_scope_and_duplicate_yaml(self):
        path = tool.ROOT / "invalid.yaml"
        path.write_text("id: first\nid: second\n")
        with self.assertRaises(tool.ToolError):
            import yaml
            yaml.load(path.read_text(), Loader=tool.CaseLoader)
        with self.assertRaises(tool.ToolError):
            tool.run_path(str(tool.ROOT))

    def test_code_contract_does_not_require_model_show(self):
        saved = tool.dispatch("save", str(ROOT / "cases"), str(self.run), "PT_WEB_04", self.payload())
        self.assertEqual(saved["result"], "通过")

    def test_saved_partial_failure_stays_pending(self):
        value = self.payload("失败")
        value["coverage_complete"] = False
        value["coverage_limitations"] = ["OFFLINE missing required branch"]
        self.save(value)
        self.assertEqual(self.check_completion()["pending_case_ids"], tool.execution_order(self.context, self.cases))
        record = tool.read_json(self.run / "evidence/PT_WEB_01.json")
        self.assertEqual(record["result"], "失败")

    def test_native_evidence_and_json_permissions(self):
        saved = self.save(self.payload())
        record = tool.read_json(Path(saved["saved_path"]))
        reference = record["evidence"][0]
        self.assertEqual(Path(reference["saved_path"]).read_bytes(), self.source.read_bytes())
        self.assertEqual(Path(saved["saved_path"]).stat().st_mode & 0o777, 0o600)

    def test_missing_empty_preview_and_bad_reference(self):
        for data in [b"", b"<persisted-output>preview</persisted-output>"]:
            self.source.write_bytes(data)
            with self.assertRaises(tool.ToolError):
                self.save(self.payload())
        self.source.unlink()
        with self.assertRaises(tool.ToolError):
            self.save(self.payload())
        self.source.write_text("fixture")
        value = self.payload()
        value["observations"][0]["evidence_ids"] = ["unknown"]
        with self.assertRaises(tool.ToolError):
            self.save(value)

    def test_failed_subitem_cannot_be_interrupted(self):
        value = self.payload("失败")
        value["result"] = "中断"
        with self.assertRaises(tool.ToolError):
            self.save(value)

    def test_failed_subitem_cannot_be_hidden_as_unselected(self):
        value = self.payload()
        value["scope_items"].append({**value["scope_items"][0], "item_id": "S2", "must_complete": False})
        value["item_results"].append({**value["item_results"][0], "item_id": "S2", "result": "失败"})
        with self.assertRaises(tool.ToolError) as raised:
            self.save(value)
        self.assertEqual(raised.exception.field, "scope_items.must_complete")

    def test_completed_evidence_required(self):
        value = self.payload()
        value["actual_steps"][0]["tool_status"] = "running"
        with self.assertRaises(tool.ToolError):
            self.save(value)

    def test_summary_credentials_filtered_without_changing_native_bytes(self):
        value = self.payload()
        value["observations"][0]["summary"] = "默认凭据admin/password123登录失败；另有admin/letmein 会话PHPSESSID=fixture-secret;令牌user_token=fixture-csrf"
        original = self.source.read_bytes()
        saved = self.save(value)
        record = tool.read_json(Path(saved["saved_path"]))
        self.assertNotIn("admin/password", record["observations"][0]["summary"])
        self.assertNotIn("letmein", record["observations"][0]["summary"])
        self.assertIn("登录失败", record["observations"][0]["summary"])
        self.assertNotIn("fixture-secret", record["observations"][0]["summary"])
        self.assertNotIn("fixture-csrf", record["observations"][0]["summary"])
        self.assertEqual(Path(record["evidence"][0]["saved_path"]).read_bytes(), original)

    def test_invented_execution_id_is_rejected(self):
        value = self.payload()
        value["actual_steps"][0]["execution_id"] = "exec-invented-001"
        with self.assertRaises(tool.ToolError) as raised:
            self.save(value)
        self.assertEqual(raised.exception.field, "actual_steps.execution_id")
        value["actual_steps"][0]["execution_id"] = "00000000-0000-4000-8000-000000000001"
        self.assertEqual(self.save(value)["result"], "通过")

    def test_invalid_exploration_columns_do_not_persist(self):
        with self.assertRaises(tool.ToolError) as raised:
            report.save_info(self.run, {"exploratory_sections": {"5.2": [{"columns": ["fixture"]}]}})
        self.assertEqual(raised.exception.field, "exploratory_sections.5.2.columns")
        self.assertFalse((self.run / "evidence/report_info.json").exists())

    def test_report_end_before_start_is_rejected(self):
        with self.assertRaises(tool.ToolError) as raised:
            report.save_info(self.run, {"test_info": {"ended_at": "2000-01-01T00:00:00Z"}})
        self.assertEqual(raised.exception.field, "test_info.ended_at")
        self.assertFalse((self.run / "evidence/report_info.json").exists())

    def test_condition_missing_has_input_fact_not_fake_output(self):
        # Legacy snapshots retain their original contract; new runs do not accept it.
        snapshot_path = self.run / "evidence/test_info.json"
        snapshot = tool.read_json(snapshot_path)
        snapshot["context"].pop("result_contract")
        tool.write_json(snapshot_path, snapshot, replace=True)
        value = self.payload("中断")
        value["interruption_kind"] = "条件缺失"
        value["actual_steps"] = []
        value["observations"] = []
        value["item_results"][0].update(observation_ids=[], evidence_ids=["E1"])
        value["evidence"] = [{"evidence_id": "E1", "source_type": "输入事实", "source_ref": "test_info.source", "coverage": "offline fixture only"}]
        reason = value.pop("interruption_reason")
        with self.assertRaises(tool.ToolError) as raised:
            self.save(value)
        self.assertEqual(raised.exception.field, "payload.interruption_reason")
        self.assertIn("顶层", str(raised.exception))
        value["interruption_reason"] = reason
        self.assertEqual(self.save(value)["result"], "中断")
        record = tool.read_json(self.run / "evidence/PT_WEB_01.json")
        self.assertEqual(record["evidence"][0]["fact_value"], "offline fixture")

    def test_environment_interruption_requires_actual_evidence(self):
        value = self.payload("中断")
        value["actual_steps"][0]["tool_status"] = "failed"
        self.assertEqual(self.save(value)["result"], "中断")
        built = self.build()
        self.assertIn("环境问题 1", Path(built["report_path"]).read_text())
        value["interruption_kind"] = "条件缺失"
        with self.assertRaises(tool.ToolError):
            self.save(value)
        value["interruption_kind"] = "环境问题"
        value["actual_steps"] = []
        value["observations"] = []
        value["item_results"][0].update(observation_ids=[], evidence_ids=[])
        with self.assertRaises(tool.ToolError):
            self.save(value)

    def test_absent_attack_surface_pass_needs_completed_discovery(self):
        value = self.payload()
        value["scope_items"][0].update(applicability_reason="OFFLINE attack surface discovery", planned_checks=["OFFLINE resource and route inventory"])
        value["item_results"][0]["reason"] = "OFFLINE confirmed mechanism not in use"
        value["judgment_reason"] = "OFFLINE only: attack surface not applicable"
        self.assertEqual(self.save(value)["result"], "通过")
        value["actual_steps"] = []
        value["observations"] = []
        value["item_results"][0].update(observation_ids=[], evidence_ids=[])
        with self.assertRaises(tool.ToolError):
            self.save(value)

    def test_input_fact_must_identify_recorded_field(self):
        value = self.payload("中断")
        value["actual_steps"] = []
        value["observations"] = []
        value["item_results"][0].update(observation_ids=[], evidence_ids=["E1"])
        for ref in ("test_info", "test_info.target_has_no_mfa"):
            value["evidence"] = [{"evidence_id": "E1", "source_type": "输入事实", "source_ref": ref, "coverage": "unverified target inference"}]
            with self.assertRaises(tool.ToolError):
                self.save(value)

    def test_derived_guidance_and_results_are_not_target_evidence(self):
        guide = tool.dispatch("show", str(ROOT / "cases"), str(self.run), "PT_WEB_01")
        for source in (self.run / "evidence/test_info.json", Path(guide["guidance_path"])):
            value = self.payload()
            value["evidence"][0]["source_path"] = str(source)
            with self.assertRaises(tool.ToolError) as raised:
                self.save(value)
            self.assertEqual(raised.exception.code, "INCOMPLETE_SOURCE")

    def test_pass_cannot_borrow_unrelated_observation(self):
        value = self.payload()
        value["scope_items"].append({**value["scope_items"][0], "item_id": "S2"})
        value["actual_steps"].append({**value["actual_steps"][0], "operation_id": "O2", "item_ids": ["S2"], "tool_status": "failed"})
        value["observations"][0]["operation_id"] = "O2"
        value["item_results"].append({**value["item_results"][0], "item_id": "S2", "result": "中断"})
        value.update(result="中断", interruption_reason="fixture", interruption_kind="证据不足")
        with self.assertRaises(tool.ToolError):
            self.save(value)

    def test_selected_case_scope_is_enforced_for_guidance(self):
        created = tool.init_run(self.cases, self.context, {"test_name": "selected", "test_info": {"targets": ["fixture"], "case_ids": ["PT_WEB_01"]}})
        listing = tool.dispatch("list", str(ROOT / "cases"), created["run_dir"])
        self.assertEqual(listing["pending"], ["PT_WEB_01"])
        self.assertEqual(len(listing["unselected"]), 43)
        with self.assertRaises(tool.ToolError):
            tool.dispatch("show", str(ROOT / "cases"), created["run_dir"], "PT_WEB_02")

    def test_same_item_cannot_join_unrelated_native_files(self):
        value = self.payload()
        other = tool.ROOT / "other-native.txt"
        other.write_text("OTHER OFFLINE OPERATION")
        value["evidence"].append({**value["evidence"][0], "evidence_id": "E2", "source_path": str(other)})
        value["item_results"][0]["evidence_ids"] = ["E2"]
        with self.assertRaises(tool.ToolError):
            self.save(value)

    def test_fact_value_comes_from_init_including_false(self):
        value = self.payload()
        value["evidence"].append({"evidence_id": "E2", "source_type": "输入事实", "source_ref": "test_info.write_authorized", "coverage": "read only", "fact_value": True})
        self.save(value)
        record = tool.read_json(self.run / "evidence/PT_WEB_01.json")
        self.assertIs(record["evidence"][1]["fact_value"], False)
        record["evidence"][1]["fact_value"] = True
        tool.write_json(self.run / "evidence/PT_WEB_01.json", record, replace=True)
        built = self.build()
        self.assertEqual(built["artifact_status"], "草稿")
        self.assertTrue(any("待核验" in gap for gap in built["gaps"]))
        self.assertEqual(built["counts"]["total"]["通过"], 0)
        self.assertEqual(built["counts"]["total"]["未执行"], 44)

    def test_pending_review_preserves_result_and_removes_formal_count(self):
        self.save(self.payload())
        tool.dispatch("mark_pending", str(ROOT / "cases"), str(self.run), "PT_WEB_01", {"reason": "OFFLINE missing semantic control"})
        record = tool.read_json(self.run / "evidence/PT_WEB_01.json")
        self.assertEqual(record["result"], "通过")
        self.assertTrue(record["verification_pending"])
        self.assertEqual(len(list((self.run / "evidence/versions").glob("*.json"))), 1)
        self.assertNotIn("PT_WEB_01", tool.dispatch("list", str(ROOT / "cases"), str(self.run))["saved"])
        self.assertEqual(self.build()["counts"]["total"]["通过"], 0)
        self.assertIn("PT_WEB_01", self.check_completion()["pending_case_ids"])
        self.save(self.payload())
        self.assertEqual(self.build()["counts"]["total"]["通过"], 1)
        self.assertEqual(self.source.read_text(), "OFFLINE FIXTURE ONLY\nNORMAL/VARIANT\n")

    def test_result_versions_and_failure_preservation(self):
        self.save(self.payload("失败"))
        self.save(self.payload("失败"))
        self.assertEqual(len(list((self.run / "evidence/versions").glob("*.json"))), 1)
        with self.assertRaises(tool.ToolError):
            self.save(self.payload())
        self.assertEqual(tool.read_json(self.run / "evidence/PT_WEB_01.json")["result"], "失败")

    def test_snapshot_change_and_duplicate_run(self):
        changed = copy.deepcopy(self.cases)
        changed["PT_WEB_01"]["name"] = "changed"
        with self.assertRaises(tool.ToolError):
            tool.snapshot_check(self.run, changed)
        with self.assertRaises(tool.ToolError):
            tool.init_run(self.cases, self.context, {"test_name": "offline-fixture", "test_info": {"targets": ["fixture"]}})

    def build(self):
        return report.dispatch("build", str(self.run), str(ROOT / "cases"), str(ROOT / "templates/pentest_report_template.md"))

    def test_partial_report_is_draft_and_preserves_static_sections(self):
        self.save(self.payload())
        built = self.build()
        self.assertEqual(built["artifact_status"], "草稿")
        self.assertEqual(built["counts"]["total"]["通过"], 1)
        self.assertEqual(built["counts"]["total"]["未执行"], 43)
        content = Path(built["report_path"]).read_text()
        for chapter in ("## 一、", "## 二、", "## 三、", "## 四、", "## 五、", "## 六、", "## 七、", "## 附录A"):
            self.assertIn(chapter, content)
        checked = report.dispatch("check", str(self.run), str(ROOT / "cases"), str(ROOT / "templates/pentest_report_template.md"), report_file=built["report_path"])
        self.assertTrue(checked["check_passed"])

    def test_complete_offline_report_statistics(self):
        for cid, case in self.cases.items():
            tool.dispatch("show", str(ROOT / "cases"), str(self.run), cid)
            tool.save_result(self.run, cid, case, self.payload())
        report.save_info(self.run, {"test_info": {"test_object": "OFFLINE-FIXTURE-NO-TARGET", "tester": "OFFLINE", "reviewer": "OFFLINE", "approver": "OFFLINE", "document_version": "OFFLINE", "acsl_grade": "OFFLINE-FIXTURE", "acsl_basis": "OFFLINE-NOT-A-SECURITY-ASSESSMENT", "ended_at": tool.datetime.now(tool.timezone.utc).isoformat()}})
        built = self.build()
        self.assertEqual(built["counts"]["total"], {"通过": 44, "失败": 0, "中断": 0, "未执行": 0})
        self.assertEqual(built["artifact_status"], "最终", built["gaps"])
        template = (ROOT / "templates/pentest_report_template.md").read_text()
        content = Path(built["report_path"]).read_text()
        self.assertEqual(content[content.index("## 附录A"):], template[template.index("## 附录A"):])

    def test_report_tampering_and_missing_raw_are_not_final(self):
        self.save(self.payload())
        built = self.build()
        Path(built["report_path"]).write_text("tampered")
        with self.assertRaises(tool.ToolError):
            report.dispatch("check", str(self.run), str(ROOT / "cases"), str(ROOT / "templates/pentest_report_template.md"), report_file=built["report_path"])
        record = tool.read_json(self.run / "evidence/PT_WEB_01.json")
        Path(record["evidence"][0]["saved_path"]).unlink()
        self.assertEqual(self.build()["artifact_status"], "草稿")

    def test_duplicate_record_and_changed_template_rejected(self):
        saved = self.save(self.payload())
        duplicate = self.run / "evidence/PT_WEB_02.json"
        duplicate.write_bytes(Path(saved["saved_path"]).read_bytes())
        with self.assertRaises(tool.ToolError):
            self.build()
        duplicate.unlink()
        changed = (ROOT / "templates/pentest_report_template.md").read_text().replace("| 用例编号 | PT_WEB_01 |", "| 用例编号 | UNKNOWN |", 1)
        with self.assertRaises(tool.ToolError):
            report.template_check(changed, self.cases)


if __name__ == "__main__":
    unittest.main()
