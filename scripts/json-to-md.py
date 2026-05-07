#!/usr/bin/env python3
"""Convert Partial MLS JSON test vectors to RFC-friendly Markdown.

By default, this script reads *-spec.json files from ./test-vectors and writes
Markdown files with the same stem into ./test-vectors. For example:

    python3 scripts/json-to-md.py
    python3 scripts/json-to-md.py test-vectors/test-vector-partial-annotated-commit-spec.json

The generated Markdown files are meant to be imported by kramdown-rfc include
directives in draft-ietf-mls-partial.md.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


MAX_OUTPUT_LINE = 79

VECTOR_TYPES = [
    "test-vector-partial-membership-proofs-spec",
    "test-vector-partial-tree-operations-spec",
    "test-vector-partial-message-syntax-spec",
    "test-vector-partial-sender-authenticated-messages-spec",
    "test-vector-partial-annotated-welcome-spec",
    "test-vector-partial-annotated-commit-spec",
    "test-vector-partial-passive-client-scenarios-spec",
]

FIELD_ORDERS = {
    "test-vector-partial-message-syntax": [
        "cipher_suite",
        "copath_hash",
        "membership_proof",
        "sender_authenticated_welcome",
        "sender_authenticated_group_info",
        "sender_authenticated_public_message",
        "sender_authenticated_private_message",
        "annotated_welcome",
        "annotated_commit",
    ],
    "test-vector-partial-membership-proofs": [
        "cipher_suite",
        "tree_hash",
        "proofs",
    ],
    "test-vector-partial-sender-authenticated-messages": [
        "cipher_suite",
        "message_type",
        "sender_authenticated_message",
    ],
    "test-vector-partial-annotated-welcome": [
        "cipher_suite",
        "key_package",
        "signature_priv",
        "encryption_priv",
        "init_priv",
        "external_psks",
        "annotated_welcome",
        "joiner_leaf_index",
        "epoch_authenticator",
    ],
    "test-vector-partial-tree-operations": [
        "cipher_suite",
        "update_path",
        "tree_hash_after",
        "resolution_index",
        "sender_membership_proof_after",
        "receiver_membership_proof_after",
        "receiver_path_state",
        "commit_secret",
    ],
    "test-vector-partial-annotated-commit": [
        "cipher_suite",
        "state_before",
        "proposals",
        "annotated_commit",
        "tree_hash_after",
        "commit_secret",
        "epoch_authenticator_after",
        "state_after",
    ],
    "test-vector-partial-passive-client-scenarios": [
        "cipher_suite",
        "key_package",
        "signature_priv",
        "encryption_priv",
        "init_priv",
        "external_psks",
        "annotated_welcome",
        "initial_epoch_authenticator",
        "epochs",
    ],
}

STRING_KEYS = {
    "base_case",
    "commit_sender_type",
    "commit_wire_format",
    "description",
    "expected_failure",
    "message_type",
    "name",
    "object_type",
    "proposal_mix",
    "title",
    "type",
}

HEX_RE = re.compile(r"^(?:[0-9a-fA-F]{2})+$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert Partial MLS JSON test vectors to Markdown."
    )
    parser.add_argument("json_files", nargs="*", type=Path, help="JSON files to convert.")
    parser.add_argument(
        "-i",
        "--input-dir",
        type=Path,
        default=Path("test-vectors"),
        help="Directory to scan for JSON files when no files are named.",
    )
    parser.add_argument(
        "-p",
        "--pattern",
        default="*-spec.json",
        help="Glob pattern to use with --input-dir when no JSON files are named.",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        help="Directory for generated Markdown. Defaults to the JSON file directory.",
    )
    parser.add_argument(
        "-w",
        "--width",
        type=int,
        default=64,
        help="Maximum hex characters per output line for byte strings.",
    )
    parser.add_argument(
        "--no-placeholders",
        action="store_true",
        help="Do not generate placeholder Markdown files for missing vector types.",
    )
    return parser.parse_args()


def int_width(key: str | None) -> int:
    if key == "cipher_suite":
        return 4

    if key == "epoch":
        return 16

    if key and (
        key.endswith("_index")
        or key.endswith("_indices")
        or key in {"leaf_index", "n_leaves", "node", "lowest_common_ancestor"}
    ):
        return 8

    if key in {"sender_filtered_direct_path", "direct_path"}:
        return 8

    return 0


def is_hex_string(key: str | None, value: str) -> bool:
    if key in STRING_KEYS:
        return False

    return value == "" or HEX_RE.fullmatch(value) is not None


def scalar_text(key: str | None, value: Any) -> str | None:
    if value is None:
        return "null"

    if isinstance(value, bool):
        return "true" if value else "false"

    if isinstance(value, int):
        width = int_width(key)
        if width:
            return f"0x{value:0{width}x}"
        return f"0x{value:x}"

    if isinstance(value, str):
        if is_hex_string(key, value):
            if value == "":
                return '""'
            return value.lower()

        return json.dumps(value)

    if isinstance(value, float):
        return repr(value)

    return None


def scalar_lines(key: str | None, value: Any, indent: int, width: int) -> list[str]:
    text = scalar_text(key, value)
    if text is None:
        raise TypeError(f"not a scalar value: {type(value).__name__}")

    if isinstance(value, str) and is_hex_string(key, value) and len(value) > width:
        chunks = [value[i : i + width].lower() for i in range(0, len(value), width)]
        return [(" " * indent) + chunk for chunk in chunks]

    return [(" " * indent) + text]


def should_split_hex(key: str | None, value: Any, prefix_len: int, width: int) -> bool:
    return (
        isinstance(value, str)
        and is_hex_string(key, value)
        and value != ""
        and (len(value) > width or prefix_len + 1 + len(value) > MAX_OUTPUT_LINE)
    )


def render_pair(key: str, value: Any, indent: int, width: int) -> list[str]:
    prefix = (" " * indent) + f"{key}:"

    if isinstance(value, dict):
        lines = [prefix]
        lines.extend(render_object(value, indent + 2, width))
        return lines

    if isinstance(value, list):
        if not value:
            return [f"{prefix} []"]

        lines = [prefix]
        lines.extend(render_list(key, value, indent + 2, width))
        return lines

    text = scalar_text(key, value)
    if text is not None and not should_split_hex(key, value, len(prefix), width):
        return [f"{prefix} {text}"]

    lines = [prefix]
    lines.extend(scalar_lines(key, value, indent + 2, width))
    return lines


def render_list(key: str | None, values: list[Any], indent: int, width: int) -> list[str]:
    lines: list[str] = []

    for value in values:
        if isinstance(value, dict):
            lines.append((" " * indent) + "-")
            lines.extend(render_object(value, indent + 2, width))
        elif isinstance(value, list):
            lines.append((" " * indent) + "-")
            lines.extend(render_list(key, value, indent + 2, width))
        else:
            text = scalar_text(key, value)
            prefix = (" " * indent) + "- "
            if text is not None and not should_split_hex(key, value, len(prefix), width):
                lines.append((" " * indent) + f"- {text}")
            else:
                lines.append((" " * indent) + "-")
                lines.extend(scalar_lines(key, value, indent + 2, width))

    return lines


def render_object(obj: dict[str, Any], indent: int, width: int) -> list[str]:
    lines: list[str] = []

    for key, value in obj.items():
        lines.extend(render_pair(key, value, indent, width))

    return lines


def render_case(case: Any, width: int) -> str:
    if isinstance(case, dict):
        lines = render_object(case, 0, width)
    elif isinstance(case, list):
        lines = render_list(None, case, 0, width)
    else:
        lines = scalar_lines(None, case, 0, width)

    return "\n".join(lines)


def fenced(block: str) -> str:
    return f"~~~ text\n{block}\n~~~"


def source_stem(source: Path) -> str:
    stem = source.stem
    if stem.endswith("-spec"):
        stem = stem[:-5]
    return stem


def order_case(case: Any, source: Path) -> Any:
    order = FIELD_ORDERS.get(source_stem(source))
    if not order or not isinstance(case, dict):
        return case

    ordered = {key: case[key] for key in order if key in case}
    ordered.update((key, value) for key, value in case.items() if key not in ordered)
    return ordered


def syntax_cases(data: Any, source: Path) -> list[dict[str, Any]] | None:
    if source_stem(source) != "test-vector-partial-message-syntax":
        return None

    cases = data if isinstance(data, list) else [data]
    order = FIELD_ORDERS["test-vector-partial-message-syntax"]
    expanded: list[dict[str, Any]] = []

    for case in cases:
        if not isinstance(case, dict):
            continue

        for key in order:
            if key == "cipher_suite" or key not in case:
                continue

            expanded.append(
                {
                    "cipher_suite": case.get("cipher_suite"),
                    key: case[key],
                }
            )

    return expanded


def render_markdown(data: Any, source: Path, width: int) -> str:
    blocks: list[str]

    if data == [] or data == {}:
        body = "No test vectors are currently included for this vector type."
    elif (expanded := syntax_cases(data, source)) is not None:
        blocks = [fenced(render_case(case, width)) for case in expanded]
        body = "\n\n".join(blocks).rstrip()
    elif isinstance(data, list):
        blocks = [fenced(render_case(order_case(case, source), width)) for case in data]
        body = "\n\n".join(blocks).rstrip()
    else:
        blocks = [fenced(render_case(order_case(data, source), width))]
        body = "\n\n".join(blocks).rstrip()

    return (
        "<!-- This file is generated by scripts/json-to-md.py. "
        "Do not edit by hand. -->\n\n"
        f"<!-- Source: {source.name} -->\n\n"
        f"{body}\n"
    )


def placeholder_markdown(vector_type: str) -> str:
    return (
        "<!-- This file is generated by scripts/json-to-md.py. "
        "Do not edit by hand. -->\n\n"
        f"<!-- Source: {vector_type}.json -->\n\n"
        "No test vectors are currently included for this vector type.\n"
    )


def output_path_for(json_file: Path, output_dir: Path | None) -> Path:
    target_dir = output_dir if output_dir is not None else json_file.parent
    return target_dir / f"{json_file.stem}.md"


def convert_file(json_file: Path, output_dir: Path | None, width: int) -> Path:
    with json_file.open("r", encoding="utf-8") as f:
        data = json.load(f)

    output_path = output_path_for(json_file, output_dir)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_markdown(data, json_file, width), encoding="utf-8")
    return output_path


def main() -> int:
    args = parse_args()

    if args.width < 8:
        print("error: --width must be at least 8", file=sys.stderr)
        return 2

    if args.json_files:
        json_files = args.json_files
    else:
        json_files = sorted(args.input_dir.glob(args.pattern))

    written: set[str] = set()

    for json_file in json_files:
        output_path = convert_file(json_file, args.output_dir, args.width)
        written.add(output_path.stem)
        print(output_path)

    if not args.no_placeholders:
        placeholder_dir = args.output_dir if args.output_dir is not None else args.input_dir
        placeholder_dir.mkdir(parents=True, exist_ok=True)

        for vector_type in VECTOR_TYPES:
            if vector_type in written:
                continue

            output_path = placeholder_dir / f"{vector_type}.md"
            if output_path.exists() and json_files:
                continue

            output_path.write_text(placeholder_markdown(vector_type), encoding="utf-8")
            print(output_path)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
