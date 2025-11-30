#!/usr/bin/env python3


import argparse
import json
import os
import time
import hashlib


from Reflected import run_xss_scan as run_xss_reflected
from SQl import run_scan as run_sqli_scan


def sha8(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()[:8]


def main():
    parser = argparse.ArgumentParser(description="Main runner for Reflected XSS + SQLi scanners")
    parser.add_argument("--url", required=True, help="Target base URL")
    parser.add_argument("--outdir", required=True, help="Root output directory")
    args = parser.parse_args()

    base_url = args.url.strip()
    root_outdir = args.outdir.strip()

   
    stamp = str(int(time.time()))
    run_id = f"run_{sha8(base_url)}_{stamp}"
    run_outdir = os.path.join(root_outdir, run_id)
    os.makedirs(run_outdir, exist_ok=True)

    
    xss_outdir = os.path.join(run_outdir, "xss_reflected")
    os.makedirs(xss_outdir, exist_ok=True)

    xss_task = {
        "task_id": f"reflected-xss-{stamp}",
        "target": {"url": base_url},
    }

    xss_summary = run_xss_reflected(xss_task, xss_outdir)
    xss_found = (xss_summary.get("stats", {}).get("xss_reflected", 0) or 0) > 0

    
    sqli_outdir = os.path.join(run_outdir, "sqli")
    os.makedirs(sqli_outdir, exist_ok=True)

    sqli_task = {
        "task_id": f"sqli-{stamp}",
        "target": {"url": base_url},
        "options": {
            "non_destructive": True,
            "max_links": 200,
        },
    }

    sqli_summary_path, sqli_summary = run_sqli_scan(sqli_task, sqli_outdir)
    sqli_found = (sqli_summary.get("findings_count", 0) or 0) > 0

   
    result = {
        "status": "ok",
        "target": base_url,
        "run_id": run_id,
        "output_root": run_outdir,
        "xss_reflected": xss_found,
        "sqli": sqli_found,
        "xss_summary": xss_summary,
        "sqli_summary": sqli_summary,
    }

    # Print JSON output
    print(json.dumps(result, ensure_ascii=False, indent=2))

   
    if xss_found or sqli_found:
        print("true")
    else:
        print("false")


if __name__ == "__main__":
    main()