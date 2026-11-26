#!/usr/bin/env python3
"""يحسب دقة ملخصات الـ AI من docs/ai-validation.csv
الدقة = الجمل الصح ÷ كل الجمل.   usage: python scripts/ai_accuracy.py [path]"""
import csv, sys
from collections import Counter, defaultdict

VERDICTS = {"صح": "correct", "correct": "correct",
            "غلط": "wrong", "wrong": "wrong",
            "ملهاش دليل": "unsupported", "unsupported": "unsupported"}

def load(path):
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))

def check(rows):
    """رجّع قايمة مشاكل في الملف (حكم ناقص/غلط، أو دليل ناقص)."""
    problems = []
    for i, r in enumerate(rows, start=2):  # السطر 1 هو العنوان
        v = (r.get("verdict") or "").strip()
        if v not in VERDICTS:
            problems.append(f"سطر {i}: الحكم '{v}' مش من (صح / غلط / ملهاش دليل)")
        if not (r.get("evidence") or "").strip():
            problems.append(f"سطر {i}: الدليل فاضي")
    return problems

def accuracy(rows):
    per, total = defaultdict(Counter), Counter()
    for r in rows:
        k = VERDICTS[r["verdict"].strip()]
        per[r["summary_id"]][k] += 1
        total[k] += 1
    return per, total

def pct(c):
    n = sum(c.values())
    return (100 * c["correct"] / n) if n else 0.0

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "docs/ai-validation.csv"
    rows = load(path)
    if not rows:
        sys.exit("الملف فاضي: لسه مفيش جمل متراجعة.")
    problems = check(rows)
    if problems:
        print("اتصلح الأول:"); [print(" -", p) for p in problems]; sys.exit(1)
    per, total = accuracy(rows)
    for sid, c in sorted(per.items()):
        print(f"{sid}: {c['correct']} صح من {sum(c.values())}  ({pct(c):.0f}%)  [غلط {c['wrong']} · ملهاش دليل {c['unsupported']}]")
    n = sum(total.values())
    print(f"\nالإجمالي: {total['correct']} جملة صح من {n}  =  دقة {pct(total):.1f}%")
