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


class CaseTests(unittest.TestCase):
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
            "actual_steps": [{"operation_id": "O1", "item_ids": ["S1"], "tool_name": "offline-fixture", "method_summary": "fixture", "tool_status": "completed"}],
            "observations": [{"observation_id": "V1", "operation_id": "O1", "summary": "fixture", "evidence_ids": ["E1"]}],
            "evidence": [{"evidence_id": "E1", "source_type": "原始文件", "source_ref": "offline-fixture-execution", "coverage": "fixture only", "source_path": str(self.source)}],
            "item_results": [{"item_id": "S1", "result": result, "reason": "fixture", "observation_ids": ["V1"], "evidence_ids": ["E1"]}],
            "result": result, "judgment_reason": "OFFLINE FORMAT TEST", "coverage_limitations": ["NO TARGET TEST"],
            "recovery": {"status": "未涉及", "evidence_ids": [], "actual_actions": [], "remaining_changes": []},
        }
        if result == "中断":
            value.update(interruption_reason="offline fixture environment unavailable", interruption_kind="环境问题")
        return value

    def save(self, payload):
        return tool.save_result(self.run, "PT_WEB_01", self.cases["PT_WEB_01"], payload)

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
        value["actual_steps"][0].pop("execution_id")
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
