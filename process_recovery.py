import re
import subprocess
import os
import idaapi
import ida_segment
import ida_kernwin
import ida_netnode
import ida_loader
import ida_ida


def get_file_base(filename):
    sp = b""
    try:
        sp = subprocess.check_output(["objdump", "-p", filename])
    except subprocess.CalledProcessError:
        pass

    mch = re.findall(rb"\nImageBase\s+([0-9a-f]+)\n", sp)
    if len(mch) == 1:
        return int(mch[0], 16)

    try:
        sp = subprocess.check_output(["readelf", "-lW", filename])
    except subprocess.CalledProcessError:
        pass

    mch = re.findall(
        rb"\n\s+LOAD\s+0x0+\s+0x([0-9a-f]+)\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+[R ][W ][E ]\s+0x[0-9a-f]+\n",
        sp,
    )
    if len(mch) == 1:
        return int(mch[0], 16)

    return None


def has_dwarf_sections(filename):
    try:
        output = subprocess.check_output(
            ["readelf", "-S", filename], stderr=subprocess.DEVNULL
        ).decode(errors="ignore")
        return ".debug_info" in output or ".debug_line" in output
    except Exception:
        return False


def find_local_debuginfo(filename):
    candidates = []
    filename = filename.rstrip()

    candidates.append(filename + ".debug")
    candidates.append(filename + ".dwarf")

    if filename.endswith(".so"):
        base_no_so = filename[:-3]
        candidates.append(base_no_so + ".debug")
        candidates.append(base_no_so + ".dwarf")

    if os.path.isabs(filename):
        debug_full_path = os.path.join("/usr/lib/debug", filename.lstrip("/"))
        candidates.append(debug_full_path + ".debug")
        candidates.append(debug_full_path + ".dwarf")
        if filename.endswith(".so"):
            base_no_so_full = debug_full_path[:-3]
            candidates.append(base_no_so_full + ".debug")
            candidates.append(base_no_so_full + ".dwarf")

    basename = os.path.basename(filename)
    candidates.append(os.path.join("/usr/lib/debug", basename + ".debug"))
    candidates.append(os.path.join("/usr/lib/debug", basename + ".dwarf"))

    for path in candidates:
        if os.path.isfile(path):
            return path

    return None


def find_debuginfo_via_debuginfod(filename):
    try:
        result = subprocess.run(
            ["debuginfod-find", "debuginfo", filename],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            debug_path = result.stdout.strip()
            if os.path.isfile(debug_path):
                return debug_path
    except Exception:
        pass
    return None


def accept_file(li, filename):
    if not re.match(r"/proc/(\d+)/mem", filename):
        return 0
    return {"format": f"{filename} dump", "processor": "metapc"}


def load_file(li, neflags, fmt):
    pid = int(re.match(r"^/proc/(\d+)/mem dump$", fmt).group(1))

    bitness = ida_kernwin.ask_buttons(
        "64-bit", "32-bit", "Cancel", 0, "What bitness is this process?"
    )
    if bitness == -1:
        return 0

    if bitness == 1:
        bitness = 2
        ida_ida.inf_set_64bit()
    elif bitness == 0:
        bitness = 1

    symbols = []
    seg = idaapi.segment_t()

    with open(f"/proc/{pid}/maps") as fd:
        for line in fd.readlines():
            mch = re.match(
                r"([0-9a-f]+)-([0-9a-f]+) ([r-])([w-])([x-])[ps] ([0-9a-f]+) [0-9a-f]+:[0-9a-f]+ \d+\s+(.*)",
                line,
            )
            start = int(mch.group(1), 16)
            end = int(mch.group(2), 16)
            r = mch.group(3) == "r"
            w = mch.group(4) == "w"
            x = mch.group(5) == "x"
            offset = int(mch.group(6), 16)
            name = mch.group(7)

            if name.startswith("[anon:"):
                continue

            seg_name = os.path.basename(name) if name else name
            seg.start_ea = start
            seg.end_ea = end
            seg.bitness = bitness
            seg.perm = 0
            if r:
                seg.perm |= ida_segment.SEGPERM_READ
            if w:
                seg.perm |= ida_segment.SEGPERM_WRITE
            if x:
                seg.perm |= ida_segment.SEGPERM_EXEC

            seg_class = "CODE" if x else "DATA"
            idaapi.add_segm_ex(seg, seg_name, seg_class, 0)
            idaapi.set_segm_addressing(idaapi.getseg(start), bitness)

            if start >= 0x8000000000000000:
                print(f"Unsupported address range {start:x}-{end:x} leaving uninitialized")
                continue

            li.seek(start)
            data = li.read(end - start)
            if data:
                idaapi.put_bytes(start, data)

            if offset == 0 and os.path.isfile(name):
                symbols.append((name, start))

    for filename, actual_base in symbols:
        orig_base = get_file_base(filename)
        if orig_base is None:
            print(f"/proc/mem DWARF loader: Couldn't load symbols for {filename}")
            continue

        debug_file = filename
        if not has_dwarf_sections(filename):
            local_debug = find_local_debuginfo(filename)
            if local_debug:
                debug_file = local_debug
                print(f"/proc/mem DWARF loader: using local debuginfo: {debug_file}")
            else:
                fetched = find_debuginfo_via_debuginfod(filename)
                if fetched:
                    debug_file = fetched
                    print(f"/proc/mem DWARF loader: using debuginfo from debuginfod: {debug_file}")
                else:
                    print(
                        f"/proc/mem DWARF loader: warning: no DWARF sections in {filename} "
                        "and no separate debuginfo found locally or via debuginfod"
                    )

        print(
            f"/proc/mem DWARF loader: file base: {orig_base:016x} "
            f"loaded base: {actual_base:016x} {debug_file}"
        )

        try:
            node = ida_netnode.netnode("$ dwarf_params")
            node.supset(1, debug_file, 83)
            node.altset(2, -orig_base + actual_base, 65)
            ida_loader.run_plugin(ida_loader.load_plugin("dwarf"), 3)
        except Exception as e:
            print(f"/proc/mem DWARF loader: exception while loading DWARF for {debug_file}: {e}")

    return 1
