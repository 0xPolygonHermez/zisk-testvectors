#!/usr/bin/env python3
"""Relinks the committed DUT ELFs (riscof_work/**/dut/my.elf) from their sources, in place.

Use it when the ZisK memory map moves: edit env/link.ld and env/model_test.h, then run

    tools/relink_dut.py --mk-suite <riscv-arch-test @ 0bf9236d> \\
                        --suite-env <riscv-arch-test of the hermeznetwork/ziskof image>/riscv-test-suite/env \\
                        --bk-suite <riscv-arch-test @ b91f98f3>

- Makefile.DUT-zisk targets: their own compile command, with the /workspace paths remapped and the
  /program run dropped. Their sources are riscv-arch-test 0bf9236d (it holds every one at its
  test_list.yaml commit_id); their suite env (arch_test.h, encoding.h) is the one in the
  hermeznetwork/ziskof image (riscv-arch-test 3.9.1), which is what reproduces the committed code.
- rv64i_m/{B,K} (not in that Makefile): sources and suite env from riscv-arch-test b91f98f3, the
  same flags, and -march from the existing ELF's Tag_RISCV_arch.
DWARF paths are mapped back to /workspace/... A disabled test (my.elf.disabled) stays disabled.
The reference signatures do not depend on the link address and are not touched.
"""
import argparse, glob, os, re, subprocess, sys
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ap = argparse.ArgumentParser()
ap.add_argument("--env", default=f"{HERE}/env", help="patched env (link.ld, model_test.h)")
ap.add_argument("--work", default=f"{HERE}/riscof_work", help="riscof_work to relink in place")
ap.add_argument("--mk-suite", required=True, help="riscv-arch-test checkout at 0bf9236d")
ap.add_argument("--suite-env", required=True, help="riscv-test-suite/env of the ziskof image")
ap.add_argument("--bk-suite", required=True, help="riscv-arch-test checkout at b91f98f3")
ap.add_argument("--cc", default="riscv64-unknown-elf-gcc")
a = ap.parse_args()
ENV, W = os.path.abspath(a.env), os.path.abspath(a.work)
MK, BK, SENV = os.path.abspath(a.mk_suite), os.path.abspath(a.bk_suite), os.path.abspath(a.suite_env)
BK_ENV = f"{BK}/riscv-test-suite/env"

def pfx(d, rel, *suites):
    m = [f"-ffile-prefix-map={d}=/workspace/output/riscof_work/{rel}/dut"]
    m += [f"-ffile-prefix-map={s}=/workspace/riscv-arch-test" for s in suites]
    m += [f"-ffile-prefix-map={ENV}=/workspace/zisk/env"]
    return " ".join(m)

jobs = []
mk = open(f"{W}/Makefile.DUT-zisk").read()
for m in re.finditer(r"@cd /workspace/output/riscof_work/(\S+)/dut; riscv64-unknown-elf-gcc (.*?); /program", mk):
    rel, args = m.group(1), m.group(2)
    d = f"{W}/{rel}/dut"
    if not os.path.isdir(d):
        continue   # pruned (privilege)
    args = args.replace("/workspace/zisk/env/", ENV + "/").replace("/workspace/zisk/env", ENV)
    args = args.replace("-I /workspace/riscv-arch-test/riscv-test-suite/env", f"-I {SENV}")
    args = args.replace("/workspace/riscv-arch-test", MK)
    jobs.append((d, f"{a.cc} {args} {pfx(d, rel, MK, os.path.dirname(os.path.dirname(SENV)))}"))

for d in sorted(glob.glob(f"{W}/rv64i_m/[BK]/src/*/dut")):
    rel = d[len(W) + 1:-len("/dut")]
    elf = f"{d}/my.elf" if os.path.exists(f"{d}/my.elf") else f"{d}/my.elf.disabled"
    attr = subprocess.run(["riscv64-unknown-elf-readelf", "-A", elf], capture_output=True, text=True).stdout
    march = re.sub(r"\d+p\d+", "", re.search(r'Tag_RISCV_arch: "([^"]+)"', attr).group(1))
    jobs.append((d, f"{a.cc} -march={march} -static -mcmodel=medany -fvisibility=hidden -nostdlib "
                    f"-nostartfiles -g -T {ENV}/link.ld -I {ENV}/ -I {BK_ENV} "
                    f"{BK}/riscv-test-suite/{rel} -o my.elf -DTEST_CASE_1=True -DXLEN=64 "
                    f"-Xlinker -Map=output.map -mabi=lp64 {pfx(d, rel, BK)}"))

def run(job):
    d, cmd = job
    disabled = os.path.exists(f"{d}/my.elf.disabled")
    r = subprocess.run(cmd, shell=True, cwd=d, capture_output=True, text=True)
    if r.returncode != 0:
        return f"FAIL {d}\n{r.stderr[-1500:]}"
    if disabled:
        os.replace(f"{d}/my.elf", f"{d}/my.elf.disabled")
    return None

with ThreadPoolExecutor(os.cpu_count()) as ex:
    errs = [e for e in ex.map(run, jobs) if e]
print(f"{len(jobs)} relinked, {len(errs)} failed")
for e in errs:
    print(e)
sys.exit(1 if errs else 0)
