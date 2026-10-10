#!/usr/bin/env python3
"""Render saved evidence into the local template; never execute tests."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
import uuid

import banma_pentest_run_cases as helper

SEVERITIES = ("严重", "高危", "中危", "低危", "信息")


def cell(value):
    return str(helper.redact(value)).replace("|", "\\|").replace("\r", "").replace("\n", "；<br />")


def valid_end_time(run, value):
    try:
        ended = datetime.fromisoformat(value)
        started = datetime.fromisoformat(helper.read_json(run / "evidence/test_info.json")["started_at"])
        return ended.tzinfo is not None and started <= ended <= datetime.now(timezone.utc)
    except (TypeError, ValueError):
        return False


def source_refs(values, records, run):
    known = {"test_info", *records}
    for cid, record in records.items():
        for e in record.get("evidence", []):
            known.add(cid + ":" + e["evidence_id"])
            known.add(e["source_ref"])
            if e.get("saved_path"):
                known.add(e["saved_path"])
    for ref in helper.array(values, "source_refs", True):
        if not isinstance(ref, str) or ref not in known:
            examples = ",".join(["test_info", *sorted(records)])
            raise helper.ToolError("INVALID_INPUT", "source_refs", "引用不存在或格式错误", "通过save_info重传资料，source_refs使用字符串数组；当前用例引用可用：" + examples + "；不要直接编辑JSON或报告")


def save_info(run, payload):
    helper.demand(isinstance(payload, dict) and set(payload) <= {"test_info", "target_profile", "exploratory_sections", "findings", "conclusion"}, "payload", "报告资料字段缺失或未知")
    path = run / "evidence/report_info.json"
    old = helper.read_json(path) if path.exists() else {}
    for key, value in payload.items():
        if key in {"test_info", "exploratory_sections"}:
            helper.demand(isinstance(value, dict), key, "需要对象")
            if key == "test_info":
                allowed = {"test_object", "tester", "tester_date", "reviewer", "reviewer_date", "approver", "approver_date", "document_version", "ended_at", "acsl_grade", "acsl_basis", "tool_versions", "local_environment", "remote_environment"}
                helper.demand(set(value) <= allowed, "test_info", "未知字段：" + ",".join(sorted(set(value) - allowed)) + "；仅补报告资料，不修改targets/授权范围")
                for field, item in value.items():
                    helper.demand(isinstance(item, dict) if field == "tool_versions" else isinstance(item, str), "test_info." + field, "字段类型错误")
                if "ended_at" in value:
                    helper.demand(valid_end_time(run, value["ended_at"]), "test_info.ended_at", "需要真实ISO时间及时区，不能早于本次init或晚于当前时间；用已有工具读取实际时间，不能猜日期")
            else:
                helper.demand(set(value) <= {f"5.{i}" for i in range(1, 10)}, key, "仅允许5.1至5.9")
                for section, rows in value.items():
                    helper.array(rows, key)
                    expected = 5 if section in {"5.2", "5.7"} else 4
                    for row in rows:
                        helper.demand(isinstance(row, dict) and isinstance(row.get("columns"), list) and len(row["columns"]) == expected, "exploratory_sections." + section + ".columns", "模板本节需要" + str(expected) + "列，按本地模板顺序填写；无真实探索结果传空数组")
            old[key] = {**old.get(key, {}), **value}
        elif key in {"target_profile", "findings"}:
            helper.array(value, key)
            old[key] = value
        else:
            helper.demand(isinstance(value, dict), key, "需要value/source_refs对象")
            old[key] = value
    if path.exists():
        helper.write_json(run / "evidence/versions" / ("report-info-" + uuid.uuid4().hex + ".json"), helper.read_json(path))
    helper.write_json(path, helper.redact(old), replace=path.exists())
    return {"saved_path": str(path), "next_action": "调用mode=build；只补已有资料，不追加目标测试"}


def inputs(run, definitions, context):
    base = helper.snapshot_check(run, definitions, context)
    extra = helper.read_json(run / "evidence/report_info.json") if (run / "evidence/report_info.json").exists() else {}
    records, gaps = {}, []
    seen = set()
    for path in (run / "evidence").glob("PT_WEB_*.json"):
        record = helper.read_json(path)
        cid = record.get("case_id")
        helper.demand(cid in definitions and cid not in seen and path.stem == cid, "case_id", "未知/重复编号或文件名不符", "TEMPLATE_MISMATCH")
        seen.add(cid)
        legal_status = isinstance(record.get("result"), str) and record["result"] in helper.RESULTS
        valid = legal_status
        valid = valid and all("execution_id" not in op or helper.valid_execution_id(op["execution_id"]) for op in record.get("actual_steps", []))
        for item in record.get("evidence", []):
            if item.get("source_type") == "输入事实":
                continue
            p = Path(item.get("saved_path", ""))
            valid = valid and p.is_file() and p.resolve().is_relative_to(run.resolve()) and helper.digest(p.read_bytes()) == item.get("sha256")
        if legal_status:
            record["_evidence_verified"] = valid
            records[cid] = record
        if not valid:
            gaps.append(cid + ": 结果/原文无效，待核验；不改写为通过或中断")
    counts = {g: {s: 0 for s in ("通过", "失败", "中断", "未执行")} for g in ("anonymous", "authenticated", "total")}
    for cid, case in definitions.items():
        status = records[cid]["result"] if cid in records else "未执行"
        counts[case["group"]][status] += 1
        counts["total"][status] += 1
        if cid not in records:
            gaps.append(cid + ": 未执行或无有效已保存结果")
    fingerprint = helper.digest(json.dumps([base, extra, records], ensure_ascii=False, sort_keys=True).encode())
    return base, extra, records, counts, gaps, fingerprint


def template_check(template, definitions):
    ids = re.findall(r"\| 用例编号 \| (PT_WEB_(?:AUTH_)?\d+) \|", template)
    helper.demand(len(ids) == len(set(ids)) and set(ids) == set(definitions), "template_file", "模板编号缺失/重复/多余", "TEMPLATE_MISMATCH")
    for cid, case in definitions.items():
        match = re.search(r"#### 4\.[23]\.\d+ " + cid + r" [^\n]+\n(.*?)(?=\n#### |\n## |\Z)", template, re.S)
        parts = ["必测：" + case["required"], "条件性：" + case["conditional"]]
        parts += [f"{i}. {s}" for i, s in enumerate(case["steps"], 1)]
        parts += ["最小证据：" + case["minimum_evidence"]]
        fields = {"用例名称": case["name"], "测试项": case["category"], "用例等级": case["level"], "用例说明": case["description"], "测试步骤": "；<br />".join(parts), "期望结果": "；<br />".join(s + "：" + case["expected_results"][s] for s in ("通过", "失败", "中断"))}
        for label, value in fields.items():
            value = value.replace("<%=7*7%>", "&lt;%=7*7%&gt;")
            helper.demand(match and "| " + label + " | " + value + " |" in match[1], cid + "." + label, "模板与YAML不一致", "TEMPLATE_MISMATCH")


def render(run, definitions, context, template):
    template_check(template, definitions)
    base, extra, records, counts, gaps, fingerprint = inputs(run, definitions, context)
    info = {**base["test_info"], **extra.get("test_info", {})}
    if info.get("ended_at") and not valid_end_time(run, info["ended_at"]):
        gaps.append("报告结束时间无效：早于本次开始、晚于当前或缺时区，须经save_info修正")
        info.pop("ended_at")
    for key in ("test_object", "tester", "reviewer", "approver", "document_version", "acsl_grade", "acsl_basis", "ended_at"):
        if not info.get(key):
            gaps.append("报告资料缺失: " + key)
    findings = list(extra.get("findings", []))
    for cid, record in records.items():
        findings += [{**f, "case_id": cid} for f in record.get("findings", [])]
    confirmed = []
    identities = set()
    for f in findings:
        cid = f.get("case_id")
        if cid not in records or not records[cid].get("_evidence_verified") or records[cid]["result"] != "失败" or f.get("severity") not in SEVERITIES or not f.get("source_refs") or not f.get("impact"):
            gaps.append("漏洞资料缺少有效失败记录/等级/影响/引用: " + str(cid))
            continue
        source_refs(f["source_refs"], records, run)
        identity = (cid, f.get("title"))
        if identity not in identities:
            confirmed.append({**f, "v_id": f"V-{len(confirmed) + 1:02}"})
            identities.add(identity)
    for cid, record in records.items():
        if record["result"] == "失败" and not any(f["case_id"] == cid for f in confirmed):
            gaps.append(cid + ": 已确认失败，漏洞资料待补充")
    result = re.sub(r"<!--.*?-->\s*", "", template, flags=re.S)
    obj = info.get("test_object") or ", ".join(base["test_info"]["targets"])
    result = result.replace("【域名或网站应用名】", cell(obj)).replace("【目标 IP:PORT】", cell(", ".join(info["targets"])))
    total = counts["total"]
    summary = f"已保存结果 {len(records)} 项：通过 {total['通过']}、失败 {total['失败']}、中断 {total['中断']}、未执行 {total['未执行']}；已验证漏洞 {len(confirmed)} 项；引用异常另见草稿缺口，原记录结果保留。"
    def field(label, value):
        nonlocal result
        result = re.sub(r"^\| " + re.escape(label) + r" \| .* \|$", lambda _: "| " + label + " | " + cell(value) + " |", result, count=1, flags=re.M)
    field("测试对象", obj)
    field("测试时间", base["started_at"] + " 至 " + info.get("ended_at", "结束时间待补充"))
    field("测试结论", info.get("acsl_grade", "未评定（缺少判级依据）"))
    field("结果描述", summary)
    for label, key, marker in (("测试人", "tester", "测试人姓名"), ("审核人", "reviewer", "审核人姓名"), ("批准人", "approver", "批准人姓名")):
        result = result.replace(f"| {label} | 【{marker}】 | 【YYYY-MM-DD】 |", "| " + label + " | " + cell(info.get(key, "未提供（待补充）")) + " | " + cell(info.get(key + "_date", "未确认")) + " |")
    result = result.replace("| 【v1.0】 | 【YYYY-MM-DD】 | 【审核人姓名】 |", "| " + cell(info.get("document_version", "草稿")) + " | " + base["started_at"][:10] + " | " + cell(info.get("reviewer", "未提供")) + " |")
    result = result.replace("| 远程环境 | 【是/否】 |", "| 远程环境 | " + cell(info.get("remote_environment", "未确认")) + " |")
    result = result.replace("| 本地环境 | 【是/否】 |", "| 本地环境 | " + cell(info.get("local_environment", "未确认")) + " |")
    used = sorted({s["tool_name"] for r in records.values() for s in r["actual_steps"]})
    versions = info.get("tool_versions", {})
    result = result.replace("【本次额外调用的外部工具及版本；未调用外部工具时写“无”】", "实际已保存工具调用；无版本资料时注明未确认。")
    result = result.replace("| 1 | 【如 nmap 7.991】 |", "\n".join(f"| {i} | {cell(n)} {cell(versions.get(n, '版本未确认'))} |" for i, n in enumerate(used, 1)) or "| 1 | 无已保存工具调用 |")
    profile = {}
    for row in extra.get("target_profile", []):
        helper.demand(isinstance(row, dict) and row.get("field") and row.get("value") and row.get("source_refs"), "target_profile", "每项需field/value/source_refs")
        source_refs(row["source_refs"], records, run)
        profile[row["field"]] = row["value"]
    start, end = result.index("## 二、"), result.index("## 三、")
    block = re.sub(r"^\| ([^|]+) \| 【.*?】 \|$", lambda m: "| " + m[1] + " | " + cell(profile.get(m[1], "未确认（无已保存依据）")) + " |", result[start:end], flags=re.M)
    result = result[:start] + block + result[end:]
    vuln_rows = "\n".join(f"| {f['v_id']} | {cell(f['title'])} | {f['severity']} | {cell(f.get('status', '待修复'))} |" for f in confirmed)
    result = result.replace("| V-01 | 【已验证漏洞】 | 【严重/高危/中危/低危/信息】 | 【待修复/已修复待复测/已关闭】 |", vuln_rows or "本次未发现已验证漏洞；不表示未覆盖范围安全。")
    result = result.replace("**分级统计**：严重 0、高危 0、中危 0、低危 0、信息 0；合计 0。", "**分级统计**：" + "、".join(f"{s} {sum(f['severity'] == s for f in confirmed)}" for s in SEVERITIES) + f"；合计 {len(confirmed)}。")
    for cid, case in definitions.items():
        record = records.get(cid)
        status = record["result"] if record else "未执行/待核验"
        result = result.replace(f"| {cid} | {case['name']} | 【通过/失败/中断】 |", f"| {cid} | {case['name']} | {status} |")
        pattern = r"(#### 4\.[23]\.\d+ " + cid + r" [^\n]+\n.*?)(?=\n#### |\n## |\Z)"
        match = re.search(pattern, result, re.S)
        detail = "无有效已保存结果，未执行或待核验；不补默认三态。"
        if record:
            detail = record["judgment_reason"] + "\n"
            if not record.get("_evidence_verified"):
                detail = "原文引用待核验：保留原记录结果，但不能据此作新的安全结论。\n" + detail
            detail += "\n".join(s["tool_name"] + ": " + s["method_summary"] for s in record["actual_steps"])
            detail += "\n观察：" + "；".join(o["summary"] for o in record["observations"])
            detail += "\n证据：" + "；".join(e.get("saved_path", e["source_ref"]) for e in record["evidence"])
            detail += "\n覆盖：" + "；".join(record["coverage_limitations"]) + "\n恢复：" + record["recovery"]["status"]
            if status == "中断":
                detail += "\n中断：" + record["interruption_kind"] + "，" + record["interruption_reason"]
        specific = [f for f in confirmed if f["case_id"] == cid]
        values = {"测试结果": status, "测试详情": detail, "漏洞等级": "、".join(f["severity"] for f in specific) or ("待补充" if status == "失败" else "不适用"), "漏洞危害": "；".join(f["impact"] for f in specific) or ("已确认失败，影响待补充" if status == "失败" else "无已验证影响"), "修复记录": "未确认" if status == "失败" else "不适用", "当前状态": "待处理" if status == "失败" else "待补测" if status != "通过" else "不适用"}
        block = match[0]
        for label, value in values.items():
            block = re.sub(r"^\| " + label + r" \| .* \|$", lambda _, label=label, value=value: "| " + label + " | " + cell(value) + " |", block, flags=re.M)
        result = result[:match.start()] + block + result[match.end():]
    for group, name in (("anonymous", "匿名"), ("authenticated", "认证"), ("total", "总计")):
        c = counts[group]
        row = "| " + name + " | " + " | ".join(str(c[s]) for s in ("通过", "失败", "中断", "未执行")) + " | " + str(sum(c.values())) + " |"
        result = re.sub(r"^\| " + name + r" \| 【0】.*$", lambda _: row, result, flags=re.M)
    a = sum(r.get("interruption_kind") == "条件缺失" for r in records.values())
    b = sum(r.get("interruption_kind") == "证据不足" for r in records.values())
    result = re.sub(r"^【中断中条件缺失.*$", f"中断主原因：条件缺失 {a}、证据不足 {b}；未执行/待核验 {total['未执行']}，不计失败。", result, flags=re.M)
    for i in range(1, 10):
        pattern = r"(### 5\." + str(i) + r" [^\n]+\n)(.*?)(?=\n### |\n## )"
        match = re.search(pattern, result, re.S)
        rows = extra.get("exploratory_sections", {}).get(f"5.{i}", [])
        rendered = "本轮未保存该项探索性结果，不追加测试。"
        if rows:
            for row in rows:
                helper.demand(isinstance(row, dict) and row.get("columns") and row.get("source_refs"), "exploratory_sections", "每行需columns/source_refs")
                source_refs(row["source_refs"], records, run)
                expected = 5 if i in {2, 7} else 4
                helper.demand(len(row["columns"]) == expected, "exploratory_sections.5." + str(i) + ".columns", "模板本节需要" + str(expected) + "列；通过save_info修正本节，不直接编辑JSON")
            rendered = "\n".join("| " + " | ".join(cell(v) for v in row["columns"]) + " |" for row in rows)
        body = re.sub(r"^\| (?:【|C-01).*?\|$", "", match[2], flags=re.M).rstrip() + "\n\n" + rendered + "\n"
        result = result[:match.start()] + match[1] + body + result[match.end():]
    for i, grades in enumerate((("严重",), ("高危",), ("中危",), ("低危", "信息")), 1):
        pattern = r"(### 6\." + str(i) + r" [^\n]+\n)(.*?)(?=\n### |\n## )"
        match = re.search(pattern, result, re.S)
        selected = [f for f in confirmed if f["severity"] in grades]
        rows = "\n".join(f"| {f['v_id']} | {cell(f['title'])} | {cell('；'.join(f.get('recommendations', [])) or '待补充（无已保存建议）')} |" for f in selected)
        if any(not f.get("recommendations") for f in selected):
            gaps.append("修复建议缺失")
        body = re.sub(r"^\| 【.*$", lambda _: rows or "本轮无此等级已验证漏洞。", match[2], flags=re.M)
        result = result[:match.start()] + match[1] + body + result[match.end():]
    conclusion = extra.get("conclusion", {})
    if conclusion.get("value"):
        source_refs(conclusion.get("source_refs"), records, run)
        summary += " " + str(conclusion["value"])
    result = re.sub(r"^【用一段话概括.*$", cell(summary + " 未执行、中断及待核验不构成安全通过。"), result, flags=re.M)
    if re.search(r"【[^】]+】", result.split("## 附录A")[0]):
        gaps.append("仍有报告必填占位")
    artifact = "草稿" if gaps else "最终"
    header = "<!-- banma-render: " + json.dumps({"artifact_status": artifact, "counts": counts}, ensure_ascii=False) + " -->\n\n"
    if gaps:
        header += "> 草稿：存在未执行或资料缺口，不能作为完整测试交付。\n\n" + "\n".join("- " + cell(g) for g in gaps) + "\n\n"
    return header + result, {"artifact_status": artifact, "counts": counts, "gaps": gaps, "source_fingerprint": fingerprint}


def dispatch(mode, run_dir, cases_dir=None, template_file=None, output_name=None, payload=None, report_file=None):
    run = helper.run_path(run_dir)
    context, definitions = helper.catalog(cases_dir)
    helper.snapshot_check(run, definitions, context)
    if mode == "save_info":
        return save_info(run, payload)
    template_path = Path(template_file or helper.ROOT / "templates/pentest_report_template.md")
    content, summary = render(run, definitions, context, template_path.read_text())
    if mode == "check":
        path = Path(helper.text(report_file, "report_file"))
        helper.demand(path.is_absolute() and path.resolve().is_relative_to(run.resolve()), "report_file", "只核对本次目录")
        saved = helper.read_json(run / "evidence/report-build.json")
        helper.demand(str(path) == saved["report_path"] and helper.digest(path.read_bytes()) == saved["report_sha256"] and summary["source_fingerprint"] == saved["source_fingerprint"] and helper.digest(template_path.read_bytes()) == saved["template_sha256"], "report_file", "报告/来源/模板发生变化，请重新build", "TEMPLATE_MISMATCH")
        return {"report_path": str(path), **summary, "check_passed": True, "next_action": "草稿明确缺口，最终说明覆盖限制"}
    helper.demand(mode == "build", "mode", "未知操作")
    name = output_name or "report.md"
    helper.demand(re.fullmatch(r"[\w.-]+\.md", name), "output_name", "需要本次目录内Markdown文件名")
    path = run / name
    if path.exists():
        path = run / (path.stem + "-" + uuid.uuid4().hex[:8] + ".md")
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        output.write(content)
    helper.write_json(run / "evidence/report-build.json", {**summary, "report_path": str(path), "report_sha256": helper.digest(path.read_bytes()), "template_sha256": helper.digest(template_path.read_bytes())}, replace=(run / "evidence/report-build.json").exists())
    return {"report_path": str(path), **summary, "next_action": "调用mode=check；草稿只补已有资料，不自动补测"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=("save_info", "build", "check"))
    for option in ("run-dir", "cases-dir", "template-file", "output-name", "payload", "report-file"):
        parser.add_argument("--" + option, required=option == "run-dir")
    args = parser.parse_args()
    try:
        payload = json.loads(args.payload, object_pairs_hook=helper.unique_json) if args.payload else None
        result = dispatch(args.mode, args.run_dir, args.cases_dir, args.template_file, args.output_name, payload, args.report_file)
        print(json.dumps({"ok": True, **result}, ensure_ascii=False, indent=2))
        return 0
    except helper.ToolError as error:
        print(json.dumps({"ok": False, "error_code": error.code, "field": error.field, "reason": str(error), "retry_hint": error.hint}, ensure_ascii=False))
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        print(json.dumps({"ok": False, "error_code": "INVALID_INPUT", "field": "payload/path", "reason": "报告资料或路径错误", "retry_hint": "修正后重试，不执行目标操作"}, ensure_ascii=False))
    return 1


if __name__ == "__main__":
    sys.exit(main())
