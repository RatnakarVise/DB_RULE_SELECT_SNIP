from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Dict, Optional, Tuple, Set, Any
import re
import json

app = FastAPI(
    title="ABAP SELECT* Analyzer/Remediator (Final Format)"
)

# ---------- Robust SELECT * detector ----------
# Handles:
#   SELECT * FROM mara INTO wa WHERE ...
#   SELECT * FROM mara WHERE ... INTO wa.
#   SELECT SINGLE * FROM mara INTO wa WHERE ...
#   SELECT * FROM mara WHERE ... INTO TABLE itab.
#   Newlines anywhere; trailing dot required.
SELECT_STAR_RE = re.compile(
    r"""
    (?P<full>
      SELECT\s+(?:SINGLE\s+)?\*\s+FROM\s+(?P<table>\w+)
      (?P<body>.*?)
      \.
    )
    """,
    re.IGNORECASE | re.DOTALL | re.VERBOSE,
)

# INTO variants anywhere inside the statement body
INTO_TABLE_RE = re.compile(r"\bINTO\s+TABLE\s+(?P<name>\w+)\b", re.IGNORECASE)
INTO_WA_RE    = re.compile(r"\bINTO\s+(?!TABLE\b)(?P<name>\w+)\b", re.IGNORECASE)

# Loops/reads/assigns to discover aliases (itab -> wa or <fs>)
LOOP_INTO_RE         = re.compile(r"LOOP\s+AT\s+(?P<itab>\w+)\s+INTO\s+(?P<wa>\w+)\s*\.", re.IGNORECASE)
LOOP_ASSIGNING_RE    = re.compile(r"LOOP\s+AT\s+(?P<itab>\w+)\s+ASSIGNING\s+<(?P<fs>\w+)>\s*\.", re.IGNORECASE)
READ_TABLE_INTO_RE   = re.compile(r"READ\s+TABLE\s+(?P<itab>\w+)[^\.]*\s+INTO\s+(?P<wa>\w+)\s*\.", re.IGNORECASE)
READ_TABLE_ASSIGNING_RE = re.compile(r"READ\s+TABLE\s+(?P<itab>\w+)[^\.]*\s+ASSIGNING\s+<(?P<fs>\w+)>\s*\.", re.IGNORECASE)
ASSIGN_FS_ITAB_RE    = re.compile(r"ASSIGN\s+(?P<itab>\w+)\s*\[[^\]]*\]\s+TO\s+<(?P<fs>\w+)>\s*\.", re.IGNORECASE)
HEADER_LINE_LOOP_RE  = re.compile(r"LOOP\s+AT\s+(?P<itab>\w+)\s*\.", re.IGNORECASE)

STRUCT_FIELD_RE_TMPL = r"(?<![A-Za-z0-9_]){name}-(?P<field>[A-Za-z0-9_]+)(?![A-Za-z0-9_])"


class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = None
    class_implementation: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    code: Optional[str] = ""


# ----------------- CORE LOGIC (UNCHANGED) ----------------- #

def find_selects(txt: str):
    out = []
    for m in SELECT_STAR_RE.finditer(txt):
        full = m.group("full")
        table = m.group("table")
        body  = m.group("body")  # includes everything up to the trailing dot
        # Try to find INTO anywhere in the body (before the trailing dot)
        mi_tab = INTO_TABLE_RE.search(body)
        mi_wa  = INTO_WA_RE.search(body) if not mi_tab else None

        if mi_tab:
            tgt_type = "itab"; tgt_name = mi_tab.group("name")
        elif mi_wa:
            tgt_type = "wa";   tgt_name = mi_wa.group("name")
        else:
            # No INTO at all -> implicit (table header line or later INTO not found)
            tgt_type = "implicit"; tgt_name = table

        out.append({
            "text": full,
            "table": table,
            "target_type": tgt_type,
            "target_name": tgt_name,
            "span": m.span(0),
        })
    return out


def build_aliases(source: str) -> Dict[str, Set[str]]:
    """Map itab -> {wa, <fs>, header-line name} for field-usage harvesting."""
    aliases: Dict[str, Set[str]] = {}

    def add(owner, alias):
        aliases.setdefault(owner, set()).add(alias)

    for m in LOOP_INTO_RE.finditer(source):
        add(m.group("itab"), m.group("wa"))
    for m in LOOP_ASSIGNING_RE.finditer(source):
        add(m.group("itab"), f"<{m.group('fs')}>")
    for m in READ_TABLE_INTO_RE.finditer(source):
        add(m.group("itab"), m.group("wa"))
    for m in READ_TABLE_ASSIGNING_RE.finditer(source):
        add(m.group("itab"), f"<{m.group('fs')}>")
    for m in ASSIGN_FS_ITAB_RE.finditer(source):
        add(m.group("itab"), f"<{m.group('fs')}>")
    for m in HEADER_LINE_LOOP_RE.finditer(source):
        add(m.group("itab"), m.group("itab"))  # header-line as WA

    return aliases


def collect_used_fields(
    flat_source: str,
    select_stmt_text: str,
    table: str,
    target_type: str,
    target_name: str,
    aliases: Dict[str, Set[str]],
) -> Tuple[Set[str], bool]:
    """
    Only collect fields that are dereferenced on the SELECT target (e.g., wa-bukrs, itab-belnr, <fs>-field).
    We do NOT collect tokens merely because they appear in WHERE.
    """
    names: Set[str] = set()
    ambiguous = False

    if target_type == "implicit":
        # If implicit, the "target" is effectively the table header line name.
        names.add(table)
    elif target_type == "itab":
        names.add(target_name)
        names |= aliases.get(target_name, set())
    else:  # wa
        names.add(target_name)

    # Heuristic: if ASSIGN COMPONENT OF STRUCTURE is used for any of our names, we mark ambiguous
    for n in names:
        patt = re.compile(
            r"ASSIGN\s+COMPONENT\s+\w+\s+OF\s+STRUCTURE\s+" + re.escape(n) + r"\b",
            re.IGNORECASE,
        )
        if patt.search(flat_source):
            ambiguous = True
            break

    fields: Set[str] = set()
    for n in names:
        patt = re.compile(STRUCT_FIELD_RE_TMPL.format(name=re.escape(n)))
        for m in patt.finditer(flat_source):
            fields.add(m.group("field").lower())

    return fields, ambiguous


def build_replacement_stmt(
    sel_text: str,
    table: str,
    fields: List[str],
    target_type: str,
    target_name: str,
) -> str:
    """
    Replace the '*' with explicit fields, keep WHERE/other clauses, and
    turn INTO into 'INTO CORRESPONDING FIELDS OF ...'.
    Works regardless of WHERE vs INTO order.
    """
    # 1) Extract head "SELECT ... FROM <table>"
    head_m = re.search(r"SELECT\s+(?:SINGLE\s+)?\*\s+FROM\s+\w+", sel_text, re.IGNORECASE)
    if not head_m:
        return sel_text  # safety
    head = head_m.group(0)

    # 2) Replace '*' with explicit list
    explicit = " ".join(sorted(fields)) if fields else "*"
    head = re.sub(r"\*", explicit, head, count=1)

    # 3) Grab the body AFTER the head (WHERE, INTO, etc.) up to the final dot
    body = sel_text[head_m.end():]
    if body.endswith("."):
        body = body[:-1]

    # 4) Normalize INTO to CORRESPONDING FIELDS
    if target_type == "itab":
        into_cf = f"INTO CORRESPONDING FIELDS OF TABLE {target_name}"
    elif target_type == "wa":
        into_cf = f"INTO CORRESPONDING FIELDS OF {target_name}"
    else:  # implicit
        # no INTO present originally; we don't force one
        into_cf = None

    # Remove any existing INTO … (table or wa)
    body_wo_into = INTO_TABLE_RE.sub("", body)
    body_wo_into = INTO_WA_RE.sub("", body_wo_into)

    # Make a tidy body: keep WHERE etc., then add standardized INTO (if any)
    parts = body_wo_into.strip()
    if into_cf:
        # Put INTO after WHERE/order-by/etc. (ABAP allows either side)
        if parts:
            stmt = f"{head}{parts}\n  {into_cf}."
        else:
            stmt = f"{head}\n  {into_cf}."
    else:
        stmt = f"{head}{parts}."
    return stmt


def apply_span_replacements(source: str, repls: List[Tuple[Tuple[int, int], str]]) -> str:
    out = source
    for (s, e), r in sorted(repls, key=lambda x: x[0][0], reverse=True):
        out = out[:s] + r + out[e:]
    return out


def concat_units(units: List[Unit]) -> str:
    return "".join((u.code or "") + "\n" for u in units)


# ----------------- FINAL FORMAT HELPERS ----------------- #

def get_line_number(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def get_line_snippet(text: str, start: int, end: int) -> str:
    """
    Multi-line logical snippet: full line(s) containing the SELECT* statement.
    Similar style to your MATNR/ORDERBY scanners.
    """
    line_start = text.rfind("\n", 0, start)
    if line_start == -1:
        line_start = 0
    else:
        line_start += 1

    line_end = text.find("\n", end)
    if line_end == -1:
        line_end = len(text)

    return text[line_start:line_end]


def build_response(
    unit: Unit,
    src: str,
    select_meta: List[Dict[str, Any]],
    remediated_code: str,
) -> Dict[str, Any]:
    """
    Build final-format response:
      - top-level pgm/inc/type/name/code/remediated_code
      - findings[] in Credit-style structure
      - keep all logical metadata (used_fields, suggested_statement, etc.)
      - severity always 'error'
      - starting_line/ending_line are absolute (unit.start_line-based)
      - snippet is multi-line snippet around the SELECT* (not just raw text)
    """
    findings = []

    for sel in select_meta:
        start = sel["span"][0]
        end = sel["span"][1]

        # Relative line number inside this unit's code
        rel_line = get_line_number(src, start)
        # First line of this block is unit.start_line (per your choice A)
        base = (unit.start_line or 1) - 1
        starting_line_abs = base + rel_line

        # Multi-line snippet
        snippet = get_line_snippet(src, start, end)
        snippet_line_count = snippet.count("\n") + 1
        ending_line_abs = starting_line_abs + snippet_line_count

        target_desc = f"{sel['target_type']} {sel['target_name']}" if sel["target_name"] else sel["target_type"]

        message = f"SELECT * detected on table {sel['table']} ({target_desc})."
        if sel.get("ambiguous"):
            message += " Used-field discovery is ambiguous due to complex usage."

        if sel.get("suggested_statement"):
            suggestion = "Replace SELECT * with the suggested explicit field list."
        else:
            suggestion = "Replace SELECT * with explicit fields based on actual usage."

        findings.append({
            "prog_name": unit.pgm_name,
            "incl_name": unit.inc_name,
            "types": unit.type,
            "blockname": unit.name,
            "starting_line": starting_line_abs,
            "ending_line": ending_line_abs,
            "issues_type": "SelectStar",
            "severity": "error",  # always error now
            "message": message,
            "suggestion": suggestion,
            "snippet": snippet.replace("\n", "\\n"),
            # extra metadata so you don't lose any logic/data:
            "table": sel["table"],
            "target_type": sel["target_type"],
            "target_name": sel["target_name"],
            "used_fields": sel.get("used_fields") or [],
            "ambiguous": sel.get("ambiguous", False),
            "suggested_fields": sel.get("suggested_fields"),
            "suggested_statement": sel.get("suggested_statement"),
        })

    return {
        "pgm_name": unit.pgm_name,
        "inc_name": unit.inc_name,
        "type": unit.type,
        "name": unit.name,
        "code": src,
        "remediated_code": remediated_code,
        "findings": findings,
    }


def process_unit(
    unit: Unit,
    flat_source: str,
    aliases: Dict[str, Set[str]],
) -> Dict[str, Any]:
    """
    Single place that:
      - finds SELECT *
      - computes used_fields / ambiguity
      - builds suggested_statement
      - applies replacements to build remediated_code
      - returns final-format response dict
    Logic is identical to the original /analyze-array + /remediate-array combined.
    """
    src = unit.code or ""
    selects = find_selects(src)

    # Build metadata and replacements (equivalent to analyze-array + remediate-array)
    select_meta: List[Dict[str, Any]] = []
    replacements: List[Tuple[Tuple[int, int], str]] = []

    for sel in selects:
        used, ambiguous = collect_used_fields(
            flat_source,
            sel["text"],
            sel["table"],
            sel["target_type"],
            sel["target_name"],
            aliases,
        )

        suggested_fields = sorted(used) if used and not ambiguous else None
        suggested_stmt = (
            build_replacement_stmt(
                sel["text"],
                sel["table"],
                suggested_fields,
                sel["target_type"],
                sel["target_name"],
            )
            if suggested_fields
            else None
        )

        meta_entry = {
            "text": sel["text"],
            "table": sel["table"],
            "target_type": sel["target_type"],
            "target_name": sel["target_name"],
            "span": sel["span"],
            "used_fields": sorted(list(used)),
            "ambiguous": ambiguous,
            "suggested_fields": suggested_fields,
            "suggested_statement": suggested_stmt,
        }
        select_meta.append(meta_entry)

        # For remediation: only non-ambiguous selects with suggested fields get replaced
        if suggested_stmt:
            replacements.append((sel["span"], suggested_stmt))

    remediated = apply_span_replacements(src, replacements) if replacements else src
    return build_response(unit, src, select_meta, remediated)


# ----------------- ENDPOINTS IN FINAL FORMAT ----------------- #

@app.post("/remediate")
def remediate_single(unit: Unit):
    units = [unit]
    flat_source = concat_units(units)
    aliases = build_aliases(flat_source)
    result = process_unit(unit, flat_source, aliases)
    return [result]


@app.post("/remediate-array")
def remediate_array(units: List[Unit]):
    flat_source = concat_units(units)
    aliases = build_aliases(flat_source)

    output: List[Dict[str, Any]] = []
    for u in units:
        result = process_unit(u, flat_source, aliases)
        output.append(result)
    return output
