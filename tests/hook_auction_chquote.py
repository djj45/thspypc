#!/usr/bin/env python
r"""Dump fixed-header buffers at confirmed CHQuote parsers in a running client.

The Shanghai auction bytes captured from the socket still contain an outer
stateful packing layer. The hlib 2.3.4 request path passes its own transport
payload to CHQuoteFile unchanged, and existing 4214/7176 captures do not use
that transport protocol. Offline RTTI, constructor, vtable, and caller analysis
confirms the hexin RVA below is CHQuoteFile's vtable +0x14 parse method. Its
input is a fixed hd*/hq* buffer, so this probe records the downstream side of
the still-unlocated 4214/7176 normalization boundary.

The locally installed Frida Python runtime is currently:
    C:\Users\23027\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe

Typical use (start/login to THS first, then run this and request the same
auction stock several times in the client):
    ...\python.exe tests\hook_auction_chquote.py --process hexin.exe

This probe is version-specific.  It only attaches; it does not launch, resume,
or otherwise automate the client.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

# Values are RVAs, not preferred virtual addresses.  They are tied to the
# binaries inspected on 2026-07-27:
#   hexin.exe CHQuoteFile vtable +0x14, RVA 0x127c8b0
#   hlib.dll 2.3.4 CHQuoteFile vtable +0x14, RVA 0x3ea40
HOOKS = {
    "hexin.exe": 0x127C8B0,
    "hlib.dll": 0x3EA40,
}

AGENT = r"""
const hookRvas = {
  "hexin.exe": 0x127c8b0,
  "hlib.dll": 0x3ea40
};
const installed = new Set();

function install(module) {
  const name = module.name.toLowerCase();
  if (!(name in hookRvas) || installed.has(name))
    return;

  const target = module.base.add(hookRvas[name]);
  Interceptor.attach(target, {
    onEnter(args) {
      const input = args[0];
      const length = args[1].toInt32();
      if (length < 6 || length > 64 * 1024 * 1024)
        return;

      try {
        const prefix = input.readByteArray(2);
        const view = new Uint8Array(prefix);
        if (view[0] !== 0x68 || (view[1] !== 0x64 && view[1] !== 0x71))
          return;

        const payload = input.readByteArray(length);
        send({
          type: "chquote",
          module: module.name,
          moduleBase: module.base.toString(),
          target: target.toString(),
          input: input.toString(),
          length: length,
          mode: args[2].toInt32(),
          self: this.context.ecx.toString(),
          returnAddress: this.returnAddress.toString(),
          backtrace: Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress)
            .map(String)
        }, payload);
      } catch (error) {
        send({
          type: "error",
          module: module.name,
          target: target.toString(),
          error: String(error)
        });
      }
    }
  });
  installed.add(name);
  send({
    type: "hooked",
    module: module.name,
    moduleBase: module.base.toString(),
    target: target.toString()
  });
}

Process.attachModuleObserver({
  onAdded(module) {
    install(module);
  }
});
"""


def fixed_header_summary(data: bytes) -> dict[str, object]:
    """Describe whether a dump already looks like a fixed CHQuote header."""
    result: dict[str, object] = {"head": data[:32].hex(" ")}
    if len(data) < 16:
        return result
    record_count = int.from_bytes(data[6:10], "little") & 0xFFFFFF
    header_length = int.from_bytes(data[10:12], "little")
    row_width = int.from_bytes(data[12:14], "little")
    field_count = int.from_bytes(data[14:16], "little") & 0x3FFF
    result.update(
        record_count=record_count,
        header_length=header_length,
        row_width=row_width,
        field_count=field_count,
        fixed_header_plausible=(
            16 <= header_length <= len(data)
            and 0 < row_width <= 4096
            and 0 < field_count <= 256
            and header_length >= 16 + field_count * 4
        ),
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--process", default="hexin.exe", help="process name or PID")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "captures_live" / "chquote_hook",
    )
    args = parser.parse_args()

    try:
        import frida
    except ImportError:
        parser.error(
            "frida is not installed in this Python; use the Hermes venv shown "
            "in this script's docstring"
        )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    metadata_path = args.output_dir / "metadata.jsonl"
    sequence = 0

    def on_message(message: dict, data: bytes | None) -> None:
        nonlocal sequence
        payload = message.get("payload", {})
        if message.get("type") == "error":
            print("agent exception:", message, file=sys.stderr)
            return
        if payload.get("type") != "chquote":
            print(json.dumps(payload, ensure_ascii=False))
            return
        if data is None:
            print("chquote message did not include bytes", file=sys.stderr)
            return

        sequence += 1
        captured = bytes(data)
        digest = hashlib.sha256(captured).hexdigest()
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        path = args.output_dir / f"chquote_{stamp}_{sequence:03}_{digest[:12]}.bin"
        path.write_bytes(captured)

        record = {
            "path": str(path),
            "sha256": digest,
            **payload,
            **fixed_header_summary(captured),
        }
        with metadata_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, ensure_ascii=False) + "\n")
        print(
            f"dumped {path.name}: module={payload['module']} "
            f"len={len(captured)} mode={payload['mode']} "
            f"fixed={record.get('fixed_header_plausible')}"
        )

    target: str | int
    try:
        target = int(args.process)
    except ValueError:
        target = args.process
    session = frida.get_local_device().attach(target)
    script = session.create_script(AGENT)
    script.on("message", on_message)
    script.load()
    print(
        f"attached to {args.process}; dumps -> {args.output_dir}\n"
        "Request the same Shanghai auction stock repeatedly, then press Ctrl+C."
    )
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass
    finally:
        session.detach()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
