#!/usr/bin/env python3
"""
smali_injector/inject_methods.py
Injects  Log.d(TAG, "METHOD=<class: rettype method(args)>")
into the entry point of every Smali method in a decompiled APK directory.

Works on ANY apktool-decompiled APK (including Android 14/15/16, R8/D8, obfuscated).
No Soot, no FlowDroid — pure text-level Smali manipulation.

Usage:
    python3 inject_methods.py <smali_root_dir> [LOG_TAG]

Example:
    apktool d myapp.apk -o myapp_dec
    python3 inject_methods.py myapp_dec MYAPP_LOG
"""

import os
import re
import sys
import argparse

# Smali snippet template — inserted right after .locals N line
# Uses two local registers (v0, v1) for the log call.
# We always bump .locals by 2 to ensure the registers are free.
LOG_SNIPPET = """\
    const-string v{TAG_REG}, "{TAG}"
    const-string v{SIG_REG}, "METHOD=<{CLASS_NAME}: {METHOD_SIG}>"
    invoke-static {{v{TAG_REG}, v{SIG_REG}}}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
"""

ABSTRACT_OR_NATIVE = re.compile(r'\s*(abstract|native)\s')
LOCALS_RE          = re.compile(r'^(\s*)\.locals\s+(\d+)', re.MULTILINE)
METHOD_START_RE    = re.compile(r'^\.method\s+(.*?)$', re.MULTILINE)
CLASS_NAME_RE      = re.compile(r'^\.class\s+.*?\s+(L[\w/$]+;)', re.MULTILINE)


def smali_type_to_str(t: str) -> str:
    """Convert Smali type descriptor to readable form."""
    mapping = {
        'V': 'void', 'Z': 'boolean', 'B': 'byte', 'C': 'char',
        'S': 'short', 'I': 'int', 'J': 'long', 'F': 'float', 'D': 'double',
    }
    if t in mapping:
        return mapping[t]
    if t.startswith('L') and t.endswith(';'):
        return t[1:-1].replace('/', '.')
    if t.startswith('['):
        return smali_type_to_str(t[1:]) + '[]'
    return t


def parse_method_sig(declaration: str) -> str:
    """Turn a .method declaration line into a readable signature string."""
    # e.g. "public static void onStop(Ljava/lang/String;I)V"
    m = re.search(r'(\S+)\(([^)]*)\)(\S+)$', declaration)
    if not m:
        return declaration.strip()
    name   = m.group(1)
    params = m.group(2)
    ret    = m.group(3)

    # Parse param types
    param_types = []
    i = 0
    while i < len(params):
        if params[i] == '[':
            # array — consume all leading [
            j = i
            while j < len(params) and params[j] == '[':
                j += 1
            if j < len(params) and params[j] == 'L':
                end = params.index(';', j) + 1
                param_types.append(smali_type_to_str(params[i:end]))
                i = end
            else:
                param_types.append(smali_type_to_str(params[i:j+1]))
                i = j + 1
        elif params[i] == 'L':
            end = params.index(';', i) + 1
            param_types.append(smali_type_to_str(params[i:end]))
            i = end
        else:
            param_types.append(smali_type_to_str(params[i]))
            i += 1

    ret_str = smali_type_to_str(ret)
    return f"{ret_str} {name}({', '.join(param_types)})"


def inject_file(filepath: str, tag: str, stats: dict) -> int:
    """Inject log calls into all methods in a .smali file. Returns injected count."""
    with open(filepath, encoding='utf-8', errors='replace') as f:
        content = f.read()

    # Get class name from .class directive
    class_match = CLASS_NAME_RE.search(content)
    class_name = class_match.group(1)[1:-1].replace('/', '.') if class_match else 'Unknown'

    lines      = content.splitlines(keepends=True)
    out_lines  = []
    injected   = 0
    i          = 0

    while i < len(lines):
        line = lines[i]
        out_lines.append(line)

        # Detect method start
        method_match = METHOD_START_RE.match(line.rstrip('\n'))
        if method_match:
            decl = method_match.group(1)

            # Skip abstract / native — they have no body
            if ABSTRACT_OR_NATIVE.search(decl):
                i += 1
                continue

            method_sig = parse_method_sig(decl)
            i += 1

            # Scan forward to find .locals line (must come before first instruction)
            found_locals = False
            while i < len(lines):
                inner = lines[i]
                out_lines.append(inner)
                i += 1

                locals_match = LOCALS_RE.match(inner)
                if locals_match:
                    indent      = locals_match.group(1)
                    old_count   = int(locals_match.group(2))
                    # Always use v0 and v1 — they are ALWAYS in the 4-bit
                    # Dalvik register range (v0-v15) and are safe to use at
                    # the very start of a method before any code executes.
                    new_count   = max(old_count, 2)

                    # Replace the .locals line we just appended
                    out_lines[-1] = f"{indent}.locals {new_count}\n"

                    # Always inject using v0 (tag) and v1 (method sig)
                    tag_reg = 0
                    sig_reg = 1

                    snippet = LOG_SNIPPET.format(
                        TAG=tag,
                        CLASS_NAME=class_name,
                        METHOD_SIG=method_sig,
                        TAG_REG=tag_reg,
                        SIG_REG=sig_reg,
                    )
                    out_lines.append(snippet)
                    injected += 1
                    found_locals = True
                    break

                # Reached end of method or another method without .locals (unusual)
                if inner.strip().startswith('.end method') or inner.strip().startswith('.method'):
                    break

            if not found_locals:
                # No .locals found — skip (constructor with only super call, etc.)
                pass
            continue

        i += 1

    new_content = ''.join(out_lines)
    if injected > 0:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)
        stats['files_modified'] += 1

    stats['methods_injected'] += injected
    return injected


def inject_dir(smali_root: str, tag: str) -> dict:
    stats = {'files_modified': 0, 'methods_injected': 0, 'files_scanned': 0}
    for root, dirs, files in os.walk(smali_root):
        for fname in files:
            if not fname.endswith('.smali'):
                continue
            fpath = os.path.join(root, fname)
            stats['files_scanned'] += 1
            inject_file(fpath, tag, stats)
    return stats


def main():
    parser = argparse.ArgumentParser(description='Smali method-entry log injector')
    parser.add_argument('smali_root', help='Root dir of apktool-decompiled APK')
    parser.add_argument('tag', nargs='?', default='SMALI_LOG', help='Logcat tag (default: SMALI_LOG)')
    args = parser.parse_args()

    if not os.path.isdir(args.smali_root):
        print(f"[ERR] Not a directory: {args.smali_root}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Scanning smali files in: {args.smali_root}")
    print(f"[*] Logcat tag: {args.tag}")
    stats = inject_dir(args.smali_root, args.tag)
    print(f"[✓] Done.")
    print(f"    Files scanned   : {stats['files_scanned']}")
    print(f"    Files modified  : {stats['files_modified']}")
    print(f"    Methods injected: {stats['methods_injected']}")


if __name__ == '__main__':
    main()
