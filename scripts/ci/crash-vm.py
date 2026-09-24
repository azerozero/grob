#!/usr/bin/env python3
"""Kill a disposable Linux guest at storage checkpoints, then verify recovery."""

import argparse
import gzip
import json
import lzma
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time


CASES = (
    "atomic-written", "atomic-synced", "atomic-renamed", "atomic-published",
    "rotation-replacement", "rotation-revoked", "deleted", "refresh-pending",
    "spend-flushed", "journal-torn",
)


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def initramfs(root, probe, kernel):
    for directory in ("bin", "dev", "proc", "sys", "tmp", "data", "modules"):
        (root / directory).mkdir(parents=True)
    shutil.copy2("/bin/busybox", root / "bin/busybox")
    (root / "bin/sh").symlink_to("busybox")
    shutil.copy2(probe, root / "probe")
    # Package the exact runner's dynamic loader/libraries, without a guest network.
    linked = run("ldd", str(probe), capture_output=True, text=True).stdout
    for library in set(re.findall(r"/[^\s()]+", linked)):
        destination = root / library.lstrip("/")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(library, destination)
    version = kernel.name.removeprefix("vmlinuz-")
    modules = []
    for driver in ("virtio_pci", "virtio_blk", "ext4"):
        dependencies = run("modprobe", "--show-depends", "--set-version", version,
                           driver, capture_output=True, text=True).stdout
        for line in dependencies.splitlines():
            if not line.startswith("insmod "):
                continue
            source = Path(line.split()[1])
            name = source.name.split(".ko")[0] + ".ko"
            if name in modules:
                continue
            modules.append(name)
            destination = root / "modules" / name
            if source.suffix == ".zst":
                with destination.open("wb") as output:
                    run("zstd", "--decompress", "--stdout", str(source), stdout=output)
            elif source.suffix == ".xz":
                destination.write_bytes(lzma.decompress(source.read_bytes()))
            elif source.suffix == ".gz":
                destination.write_bytes(gzip.decompress(source.read_bytes()))
            else:
                shutil.copy2(source, destination)
    module_commands = "\n".join(f"insmod /modules/{name}" for name in modules)
    (root / "init").write_text("""#!/bin/sh
set -eu
export PATH=/bin
/bin/busybox --install -s /bin
trap 'echo GROB_VM_FAILED; poweroff -f' EXIT
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
""" + module_commands + """
mount -t ext4 /dev/vda /data
for argument in $(cat /proc/cmdline); do
    case "$argument" in
        grob_phase=*) export GROB_VM_PHASE="${argument#grob_phase=}" ;;
        grob_case=*) export GROB_VM_CASE="${argument#grob_case=}" ;;
    esac
done
/probe --exact storage::vm_crash_tests::vm_probe --ignored --nocapture --test-threads=1
sync
umount /data
echo "GROB_VM_PASS:$GROB_VM_PHASE:$GROB_VM_CASE"
trap - EXIT
poweroff -f
""")
    (root / "init").chmod(0o755)
    archive = root.parent / "guest.cpio.gz"
    names = ["."] + sorted(str(path.relative_to(root)) for path in root.rglob("*"))
    packed = run("cpio", "--null", "-o", "--format=newc", cwd=root,
                 input=("\0".join(names) + "\0").encode(), capture_output=True).stdout
    with gzip.open(archive, "wb", compresslevel=1) as output:
        output.write(packed)
    return archive


def boot(kernel, archive, disk, phase, case, output):
    log = output / f"{case}-{phase}.log"
    command = [
        "qemu-system-x86_64", "-accel", "tcg", "-cpu", "max", "-m", "1024",
        "-smp", "2", "-nographic", "-monitor", "none", "-nic", "none",
        "-no-reboot", "-kernel", str(kernel), "-initrd", str(archive),
        "-append", f"console=ttyS0 quiet panic=1 grob_phase={phase} grob_case={case}",
        "-rtc", "base=2026-01-15T12:00:00,clock=vm",
        "-drive", f"file={disk},format=raw,if=virtio,cache=writeback",
    ]
    marker = f"GROB_VM_CUT_READY:{case}" if phase == "cut" else f"GROB_VM_PASS:{phase}:{case}"
    with log.open("wb") as capture, subprocess.Popen(
        command, stdin=subprocess.DEVNULL, stdout=capture, stderr=subprocess.STDOUT
    ) as guest:
        try:
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                text = log.read_text(errors="replace")
                if "GROB_VM_FAILED" in text:
                    raise RuntimeError(f"guest assertion failed: {log}")
                if marker in text:
                    if phase == "cut":
                        # SIGKILL the VM, not just Grob. No guest sync/unmount runs.
                        guest.kill()
                    guest.wait(timeout=15)
                    if phase != "cut" and guest.returncode != 0:
                        raise RuntimeError(f"guest exited {guest.returncode}: {log}")
                    return
                if guest.poll() is not None:
                    raise RuntimeError(f"guest exited before checkpoint: {log}")
                time.sleep(0.02)
            raise TimeoutError(f"guest did not reach checkpoint: {log}")
        finally:
            if guest.poll() is None:
                guest.kill()
                guest.wait(timeout=15)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.uname().sysname != "Linux" or os.uname().machine != "x86_64":
        parser.error("requires a disposable x86_64 Linux runner")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    results = []
    with tempfile.TemporaryDirectory(prefix="grob-crash-vm-") as directory:
        work = Path(directory)
        archive = initramfs(work / "root", args.probe.resolve(), args.kernel.resolve())
        baseline = work / "baseline.raw"
        with baseline.open("wb") as disk:
            disk.truncate(128 * 1024 * 1024)
        run("mkfs.ext4", "-q", "-F", str(baseline))
        boot(args.kernel, archive, baseline, "prepare", "baseline", output)
        for case in CASES:
            disk = work / "case.raw"
            shutil.copyfile(baseline, disk)
            boot(args.kernel, archive, disk, "cut", case, output)
            boot(args.kernel, archive, disk, "verify", case, output)
            results.append({"case": case, "result": "passed"})
            (output / "recovery.json").write_text(json.dumps({
                "kernel": args.kernel.name, "filesystem": "ext4", "cache": "writeback",
                "fault": "SIGKILL QEMU; guest RAM and kernel page cache lost",
                "boundary": "host caches and physical disk firmware remain powered",
                "cases": results,
            }, indent=2) + "\n")
            print(f"PASS VM recovery: {case}", flush=True)


if __name__ == "__main__":
    main()
