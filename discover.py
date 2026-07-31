#!/usr/bin/env python3
"""
Discovery In-Depth — Orchestrator

Single entry point that runs the full discovery pipeline:
  1. service_enumerator.py  — what services have resources?
  2. auto_template.py       — generate templates for discovered services
  3. deep_discover.py       — detailed inventory using all templates
  4. graph_discover.py      — audience-driven architecture views

Usage:
    python3 discover.py --label my-project --region us-east-1
    python3 discover.py --label govcloud-prod --region us-gov-west-1
    python3 discover.py --resume output/my-project/us-east-1/20260504-183545/
"""

import argparse
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Step markers — files whose existence indicates a step completed ──
STEP_MARKERS = {
    'enumerate': 'enum-results.yaml',
    'auto-template': 'auto-templates',
    'deep-discover': None,  # checked by glob for inventory-*.yaml
    'graph': None,          # checked by glob for architecture-*.md
}


def sanitize_label(label: str) -> str:
    """Sanitize label to safe directory name.

    Allows alphanumeric, hyphens, underscores. Strips everything else.
    """
    cleaned = re.sub(r'[^a-zA-Z0-9_\-]', '', label)
    if not cleaned:
        print("ERROR: Label must contain at least one alphanumeric character.")
        sys.exit(1)
    if cleaned != label:
        print(f"  Label sanitized: '{label}' → '{cleaned}'")
    return cleaned


def run_step(step_name: str, cmd: list, errors: list,
             cwd: str = SCRIPT_DIR) -> bool:
    """Run a subprocess step, capturing output and errors.

    Returns True on success, False on failure.
    """
    print(f"\n{'─' * 60}")
    print(f"Step: {step_name}")
    print(f"{'─' * 60}")
    print(f"  Command: {' '.join(cmd)}")
    print()

    start = time.time()
    try:
        result = subprocess.run(
            cmd, cwd=cwd,
            capture_output=False,  # let output stream to terminal
            text=True,
        )
        elapsed = round(time.time() - start, 1)

        if result.returncode != 0:
            msg = f"{step_name} exited with code {result.returncode} ({elapsed}s)"
            print(f"\n  ✗ {msg}")
            errors.append(msg)
            return False

        print(f"\n  ✓ {step_name} completed ({elapsed}s)")
        return True

    except FileNotFoundError:
        msg = f"{step_name}: python3 not found"
        print(f"\n  ✗ {msg}")
        errors.append(msg)
        return False
    except Exception as e:
        msg = f"{step_name}: {type(e).__name__}: {str(e)[:200]}"
        print(f"\n  ✗ {msg}")
        errors.append(msg)
        return False


def step_completed(run_dir: str, step: str) -> bool:
    """Check if a pipeline step already completed in this run directory."""
    import glob as _glob

    if step == 'enumerate':
        return os.path.isfile(os.path.join(run_dir, 'enum-results.yaml'))

    elif step == 'auto-template':
        # Check both old and new folder names for backwards compatibility
        for dirname in ('_discovery-schemas', 'auto-templates'):
            auto_dir = os.path.join(run_dir, dirname)
            if os.path.isdir(auto_dir):
                if len(_glob.glob(os.path.join(auto_dir, '*.yaml'))) > 0:
                    return True
        return False

    elif step == 'deep-discover':
        return len(_glob.glob(os.path.join(run_dir, 'inventory-*.yaml'))) > 0

    elif step == 'graph':
        return len(_glob.glob(os.path.join(run_dir, 'architecture-*.md'))) > 0

    elif step == 'iac-blueprint':
        iac_dir = os.path.join(run_dir, 'iac-templates')
        if not os.path.isdir(iac_dir):
            return False
        # v3 writes to iac-templates/templates/, v1 writes directly to iac-templates/
        templates_dir = os.path.join(iac_dir, 'templates')
        if os.path.isdir(templates_dir):
            return len(_glob.glob(os.path.join(templates_dir, '*.yaml'))) > 0
        # Fallback: v1 layout (templates directly in iac-templates/)
        return len(_glob.glob(os.path.join(iac_dir, '*.yaml'))) > 0

    elif step == 'dr-assess':
        return os.path.isfile(os.path.join(run_dir, 'dr-gaps.md'))

    return False


def write_errors(run_dir: str, errors: list, region: str, label: str):
    """Write errors.md to the run directory."""
    filepath = os.path.join(run_dir, 'errors.md')
    with open(filepath, 'w', newline='\n') as f:
        f.write(f"# Discovery Errors — {label} / {region}\n\n")
        f.write(f"Run: `{os.path.basename(run_dir)}`\n\n")
        if errors:
            f.write(f"## {len(errors)} Error(s)\n\n")
            for err in errors:
                f.write(f"- {err}\n")
        else:
            f.write("No errors encountered.\n")
    print(f"  Error log → {filepath}")


def main():
    parser = argparse.ArgumentParser(
        description='Discovery In-Depth — Full AWS inventory pipeline.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 discover.py --label my-project --region us-east-1
  python3 discover.py --label govcloud-prod --region us-gov-west-1
  python3 discover.py --resume output/my-project/us-east-1/20260504-183545/
        """,
    )
    parser.add_argument('--label', default='',
                        help='Customer/project label (required unless --resume)')
    parser.add_argument('--region', default='',
                        help='AWS region to scan (required unless --resume)')
    parser.add_argument('--resume', default='',
                        help='Resume from an existing run directory')
    parser.add_argument('--workers', type=int, default=20,
                        help='Thread pool size for enumerator (default: 20)')
    args = parser.parse_args()

    errors = []

    # ── Determine run directory ──
    if args.resume:
        run_dir = os.path.abspath(args.resume)
        if not os.path.isdir(run_dir):
            print(f"ERROR: Resume directory does not exist: {run_dir}")
            sys.exit(1)
        # Extract region from existing inventory or directory path
        # Path convention: output/<label>/<region>/<timestamp>/
        parts = run_dir.rstrip(os.sep).split(os.sep)
        if len(parts) >= 3:
            region = parts[-2]
            label = parts[-3]
        else:
            print("ERROR: Cannot determine label/region from resume path.")
            print("Expected: output/<label>/<region>/<timestamp>/")
            sys.exit(1)
        print(f"Resuming run: {run_dir}")
        print(f"  Label:  {label}")
        print(f"  Region: {region}")
    else:
        if not args.label or not args.region:
            print("ERROR: --label and --region are required (or use --resume)")
            parser.print_help()
            sys.exit(1)

        label = sanitize_label(args.label)
        region = args.region
        timestamp = datetime.now(tz=timezone.utc).strftime('%Y%m%d-%H%M%S')
        run_dir = os.path.join(SCRIPT_DIR, 'output', label, region, timestamp)
        os.makedirs(run_dir, exist_ok=True)

    # Use _discovery-schemas for new runs; fall back to auto-templates for resumed old runs
    auto_template_dir = os.path.join(run_dir, '_discovery-schemas')
    old_auto_dir = os.path.join(run_dir, 'auto-templates')
    if os.path.isdir(old_auto_dir) and not os.path.isdir(auto_template_dir):
        # Resuming an old run — use the existing folder
        auto_template_dir = old_auto_dir
    else:
        os.makedirs(auto_template_dir, exist_ok=True)

    enum_output = os.path.join(run_dir, 'enum-results.yaml')
    template_dir = os.path.join(SCRIPT_DIR, 'templates')

    print(f"\n{'═' * 60}")
    print(f"Discovery In-Depth — {label} / {region}")
    print(f"{'═' * 60}")
    print(f"  Output: {run_dir}")
    print(f"{'═' * 60}")

    # ── Step 1: Service Enumeration ──
    if step_completed(run_dir, 'enumerate'):
        print(f"\n  ⏭  Enumerate: already completed, skipping")
    else:
        ok = run_step('Service Enumeration', [
            sys.executable,
            os.path.join(SCRIPT_DIR, 'service_enumerator.py'),
            '--region', region,
            '--workers', str(args.workers),
            '--output', enum_output,
        ], errors)
        if not ok:
            print("\nEnumeration failed. Fix the issue and --resume.")
            write_errors(run_dir, errors, region, label)
            sys.exit(1)

    # ── Step 2: Auto-Template Generation ──
    if step_completed(run_dir, 'auto-template'):
        print(f"\n  ⏭  Auto-Template: already completed, skipping")
    else:
        ok = run_step('Auto-Template Generation', [
            sys.executable,
            os.path.join(SCRIPT_DIR, 'auto_template.py'),
            '--region', region,
            '--from-enum', enum_output,
            '--output', auto_template_dir,
        ], errors)
        if not ok:
            # Non-fatal — we can still run with hand-crafted templates
            errors.append("Auto-template generation failed; "
                          "continuing with hand-crafted templates only")
            print("  ⚠  Continuing with hand-crafted templates only")

    # ── Step 3: Deep Discovery ──
    if step_completed(run_dir, 'deep-discover'):
        print(f"\n  ⏭  Deep Discovery: already completed, skipping")
    else:
        ok = run_step('Deep Discovery', [
            sys.executable,
            os.path.join(SCRIPT_DIR, 'deep_discover.py'),
            '--region', region,
            '--output', run_dir,
            '--templates', template_dir,
            '--auto-templates', auto_template_dir,
        ], errors)
        if not ok:
            print("\nDeep discovery failed. Fix the issue and --resume.")
            write_errors(run_dir, errors, region, label)
            sys.exit(1)

    # ── Step 4: Graph Discovery (all audiences) ──
    if step_completed(run_dir, 'graph'):
        print(f"\n  ⏭  Graph Discovery: already completed, skipping")
    else:
        inventory_file = os.path.join(run_dir, f'inventory-{region}.yaml')
        if not os.path.isfile(inventory_file):
            msg = f"Inventory file not found: {inventory_file}"
            errors.append(msg)
            print(f"\n  ✗ {msg}")
        else:
            ok = run_step('Graph Discovery', [
                sys.executable,
                os.path.join(SCRIPT_DIR, 'graph_discover.py'),
                '--input', inventory_file,
                '--audience', 'all',
                '--output', run_dir,
            ], errors)
            if not ok:
                errors.append("Graph discovery failed; "
                              "inventory files are still available")

    # ── Step 5: CFN Schema Cache (for immutables enforcement) ──
    schema_cache_marker = os.path.expanduser(f'~/.cfn-schemas/{region}')
    if os.path.isdir(schema_cache_marker) and len(os.listdir(schema_cache_marker)) > 10:
        print(f"\n  ⏭  Schema Cache: already populated ({len(os.listdir(schema_cache_marker))} types), skipping")
    else:
        ok = run_step('CFN Schema Cache', [
            sys.executable,
            os.path.join(SCRIPT_DIR, 'cfn_schema_cache.py'),
            '--region', region,
        ], errors)
        if not ok:
            errors.append("CFN schema cache build failed; "
                          "IaC templates will generate without immutables enforcement")
            print("  ⚠  Continuing without schema cache (immutables not enforced)")

    # ── Step 6: IaC Blueprint Generation ──
    if step_completed(run_dir, 'iac-blueprint'):
        print(f"\n  ⏭  IaC Blueprint: already completed, skipping")
    else:
        inventory_file = os.path.join(run_dir, f'inventory-{region}.yaml')
        if not os.path.isfile(inventory_file):
            msg = f"Inventory file not found for IaC generation: {inventory_file}"
            errors.append(msg)
            print(f"\n  ✗ {msg}")
        else:
            ok = run_step('IaC Blueprint Generation', [
                sys.executable,
                os.path.join(SCRIPT_DIR, 'iac_blueprint.py'),
                '--input', run_dir,
            ], errors)
            if not ok:
                errors.append("IaC blueprint generation failed; "
                              "inventory and architecture docs are still available")
                print("  ⚠  Continuing without IaC templates")

    # ── Step 7: DR Readiness Assessment ──
    if step_completed(run_dir, 'dr-assess'):
        print(f"\n  ⏭  DR Assessment: already completed, skipping")
    else:
        inventory_file = os.path.join(run_dir, f'inventory-{region}.yaml')
        if not os.path.isfile(inventory_file):
            msg = f"Inventory file not found for DR assessment: {inventory_file}"
            errors.append(msg)
            print(f"\n  ✗ {msg}")
        else:
            ok = run_step('DR Readiness Assessment', [
                sys.executable,
                os.path.join(SCRIPT_DIR, 'dr_assess.py'),
                '--input', run_dir,
            ], errors)
            if not ok:
                errors.append("DR assessment failed; other deliverables are still available")
                print("  ⚠  Continuing without DR gap report")

    # ── Write error log ──
    write_errors(run_dir, errors, region, label)

    # ── Summary ──
    print(f"\n{'═' * 60}")
    print(f"Pipeline Complete — {label} / {region}")
    print(f"{'═' * 60}")
    print(f"  Output: {run_dir}")
    if errors:
        print(f"  Errors: {len(errors)} (see errors.md)")
    else:
        print(f"  Errors: none")
    print(f"{'═' * 60}")

    # Highlight key deliverables
    iac_dir = os.path.join(run_dir, 'iac-templates')
    if os.path.isdir(iac_dir):
        print(f"\n  ╭─ DELIVERABLES ──────────────────────────────────────╮")
        print(f"  │  CloudFormation Templates:  iac-templates/templates/ │")
        print(f"  │  Parameter Files:           iac-templates/params/    │")
        print(f"  │  Deployment Guide:          iac-templates/DEPLOY.md  │")
        print(f"  │  Architecture Docs:         architecture-*.md        │")
        print(f"  │  DR Gap Report:             dr-gaps.md               │")
        print(f"  ╰─────────────────────────────────────────────────────╯")
    else:
        print(f"\n  ╭─ DELIVERABLES ──────────────────────────────────────╮")
        print(f"  │  Inventory:         inventory-{region}.yaml")
        print(f"  │  Architecture Docs: architecture-*.md")
        print(f"  │  NOTE: IaC templates were not generated (see errors) │")
        print(f"  ╰─────────────────────────────────────────────────────╯")

    print(f"\n  All output files:")

    # List what was produced
    for f in sorted(os.listdir(run_dir)):
        full = os.path.join(run_dir, f)
        if os.path.isdir(full):
            count = len([x for x in os.listdir(full) if x.endswith('.yaml')])
            if f.startswith('_'):
                print(f"    📁 {f}/ ({count} files) [internal]")
            else:
                print(f"    📁 {f}/ ({count} files)")
        else:
            size = os.path.getsize(full)
            if size > 1024 * 1024:
                size_str = f"{size / (1024*1024):.1f} MB"
            elif size > 1024:
                size_str = f"{size / 1024:.1f} KB"
            else:
                size_str = f"{size} B"
            print(f"    📄 {f} ({size_str})")

    print()


if __name__ == '__main__':
    main()
