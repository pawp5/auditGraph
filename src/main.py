"""AuditGraph CLI:  python -m src.main <command>

  ingest <file.sol> [--version v1]   compile with Slither, write the code property graph
  audit [--no-llm] [--full]          Scanner -> Verifier on the impact set (or everything)
  triage <finding_id> <status> --note "..."
  findings                           list findings stored in the graph
  diff                               show changed functions and the re-audit impact set
  report [-o report.md]              Reporter writes markdown from graph state
  reset                              drop the graph
"""
import argparse
import sys

from rich.console import Console
from rich.table import Table

from . import diff
from .agents import Reporter, Scanner, Verifier, VerifierError
from .ingest import IngestError, ingest_file
from .schema import GraphUnavailable, ensure_schema, get_graph, reset

console = Console()


def cmd_ingest(g, a):
    stats = ingest_file(g, a.file, a.version)
    console.print(f"[green]Ingested[/] {a.file} as {a.version}: {stats}")
    changes = diff.version_diff(g, a.version)
    if changes:
        t = Table("contract", "function", "change", title="Changed vs previous ingest")
        for row in changes:
            t.add_row(*row)
        console.print(t)


def cmd_audit(g, a):
    scope = None if a.full else diff.impact_set(g)
    if scope == []:
        console.print("Nothing changed since the last audit. Use --full to re-scan everything.")
        return
    console.print(f"[bold]Scope:[/] {'entire graph' if scope is None else f'{len(scope)} functions (impact set)'}")
    if scope:
        console.print("  " + ", ".join(scope))
    version = g.query("MATCH (c:Contract) RETURN max(c.version)").result_set[0][0]
    s = Scanner(g).run(scope, version)
    console.print(f"[cyan]Scanner[/]  matched={s['matched']} new={s['new']} resolved={s['resolved']}")
    v = Verifier(g, use_llm=not a.no_llm).run()
    console.print(f"[cyan]Verifier[/] {'mock' if a.no_llm else 'llm'}: {v}")
    all_ids = [r[0] for r in g.query("MATCH (f:Function) RETURN f.id").result_set]
    diff.mark_audited(g, scope if scope is not None else all_ids)
    cmd_findings(g, a)


def cmd_findings(g, a):
    rows = g.query("""MATCH (fd:Finding) RETURN fd.id, fd.status, fd.severity, fd.key,
                      coalesce(fd.resolved_in, ''), coalesce(fd.triage_note, '') ORDER BY fd.key""").result_set
    t = Table("id", "status", "severity", "pattern:function", "resolved_in", "triage note", title="Findings (graph state)")
    colors = {"confirmed": "red", "dismissed": "dim", "candidate": "yellow"}
    for r in rows:
        t.add_row(r[0], f"[{colors.get(r[1], 'white')}]{r[1]}[/]", *[str(x) for x in r[2:]])
    console.print(t)


def cmd_triage(g, a):
    if diff.triage(g, a.finding_id, a.status, a.note):
        console.print(f"[green]{a.finding_id} -> {a.status}[/] ({a.note})")
    else:
        console.print(f"[red]No finding with id {a.finding_id}[/]")
        sys.exit(1)


def cmd_diff(g, a):
    version = g.query("MATCH (c:Contract) RETURN max(c.version)").result_set[0][0]
    for row in diff.version_diff(g, version):
        console.print("  ", *row)
    console.print("[bold]Impact set (changed since last audit + 1-hop callers):[/]", diff.impact_set(g))


def cmd_report(g, a):
    console.print(f"[green]Report written:[/] {Reporter(g).write(a.output)}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="auditgraph")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("ingest"); s.add_argument("file"); s.add_argument("--version", default="v1")
    s = sub.add_parser("audit"); s.add_argument("--no-llm", action="store_true"); s.add_argument("--full", action="store_true")
    s = sub.add_parser("triage"); s.add_argument("finding_id"); s.add_argument("status"); s.add_argument("--note", default="")
    sub.add_parser("findings"); sub.add_parser("diff"); sub.add_parser("reset")
    s = sub.add_parser("report"); s.add_argument("-o", "--output", default="report.md")
    a = p.parse_args(argv)
    try:
        g = get_graph()
        if a.cmd == "reset":
            reset(g)
            console.print("Graph dropped.")
            return
        ensure_schema(g)
        {"ingest": cmd_ingest, "audit": cmd_audit, "triage": cmd_triage, "findings": cmd_findings,
         "diff": cmd_diff, "report": cmd_report}[a.cmd](g, a)
    except (GraphUnavailable, IngestError, VerifierError, ValueError) as e:
        console.print(f"[red]Error:[/] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
