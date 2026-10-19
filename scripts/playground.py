"""Start a throwaway Postgres loaded with the vulnerable example app, without Docker.

    uv run python scripts/playground.py

A menu explains what is going on and runs se-check against the example for you.
Quitting (q, Ctrl+C, or closing the terminal) stops the database and deletes it.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
from collections.abc import Callable
from pathlib import Path

import pgserver
import psycopg

PROJECT_DIR = Path(__file__).resolve().parent.parent
EXAMPLE_DIR = PROJECT_DIR / "examples" / "vulnerable-app"
RULE = "─" * 76


def banner(dsn: str) -> str:
    return textwrap.dedent(f"""
        {RULE}
         se-check playground
        {RULE}
        A throwaway Postgres database is now running on this computer. It holds
        "Acme Notes", a small multi-tenant app full of security holes put there on
        purpose (examples/vulnerable-app/10_acme_notes.sql). Your real databases
        are not involved, and this one is deleted when you quit.

        Its address (the connection string, or DSN) is:
          {dsn}""")


def guide_command_parts(dsn: str) -> str:
    return textwrap.dedent("""
        Every se-check command has the same shape. Take the audit from option 2:

          uv run se-check audit --min-severity high

          uv run               runs a program with this project's dependencies.
                               Needed until you install se-check: after that
                               (see option 9) you type just `se-check`.
          se-check             the program.
          audit                what to do: analyze the database. `checks` lists
                               the checks; `mcp` starts the MCP server.
          --min-severity high  an option: hide the findings below high.

        Which database? In a Supabase project folder se-check finds the local one
        by itself (or the hosted one with --linked). Here there is no project
        folder, so this menu hands it the address in the SE_CHECK_DSN variable.

        Other useful options:
          --format json   machine-readable output
          --help          all the options: uv run se-check audit --help""")


def guide_run_yourself(dsn: str) -> str:
    return textwrap.dedent(f"""
        Keep this window open: closing it stops the database. Open a second
        terminal and type:

          cd {PROJECT_DIR}
          export SE_CHECK_DSN='{dsn}'
          uv run se-check audit

        `cd` enters the se-check folder, where uv finds the program.
        `export` stores the database address in a variable se-check reads. It
        lasts until you close that terminal. You can also skip it and pass the
        address in the command itself:

          uv run se-check audit --dsn '{dsn}'

        The command exits with status 1 when there are high or critical findings
        (0 otherwise): that is what lets se-check fail a CI build.""")


def guide_own_database(dsn: str) -> str:
    return textwrap.dedent(f"""
        Install se-check once, so it works from any folder:

          uv tool install --editable {PROJECT_DIR}

        Then go to your Supabase project folder (the one with supabase/config.toml)
        and run:

          se-check audit            the local database, the one `supabase start` runs
          se-check audit --linked   the hosted project you linked with `supabase link`:
                                    it only asks for the database password

        No Supabase CLI? Run `se-check audit` anywhere and paste a connection string
        when it asks (Dashboard → Connect → Session pooler).

        se-check only reads the structure of the database (tables, policies,
        functions), never the data in it, and only in read-only mode. The one
        exception is --probe (option 6), which writes synthetic rows inside a
        transaction it always rolls back.""")


def guide_probe(dsn: str) -> str:
    return textwrap.dedent("""
        The checks read definitions. The probe (`se-check audit --probe`) tries
        them: inside one transaction, which it always rolls back, it creates
        synthetic tenants A and B, users and rows, then acts as

          anon       a request with only the anon key, which ships with your app
          alice      a logged-in member of tenant A
          outsider   a logged-in user who belongs to no tenant
          mallory    a user who wrote tenant B into her own user_metadata

        and tries to read, update, delete and insert tenant B's rows (or bob's,
        on tables of private rows), the way the Data API would. Alice also tries
        to make herself admin on her own profile. What gets through becomes a
        probe-* finding; when a static check flagged the same hole, the finding
        says it confirms it. On this example, profiles shows a hole no static
        check sees: users can set their own role.

        It only touches rows it created and reports no data. It writes, though:
        it runs on local databases (the local stack, CI) unless you add
        --probe-remote. "No findings" only means something for the tables it
        reached: the line under the title says how many those are, and warns
        when it is not all of them. The report ends with the tables it did not
        reach, grouped by the row that was missing, and what to do about it.""")


def guide_ai_agent(dsn: str) -> str:
    return textwrap.dedent(f"""
        As an MCP server, se-check lets an AI agent (Claude Code, Cursor, ...)
        audit the database by itself, for example right after writing a migration.
        The agent gets two tools: audit_database and list_checks.

        For your own project, once se-check is installed (option 9), run this in
        the project folder:

          claude mcp add se-check -- se-check mcp --project "$PWD"

        To try it right now on this example database instead:

          claude mcp add se-check -e SE_CHECK_DSN='{dsn}' -- \\
            uv run --directory {PROJECT_DIR} se-check mcp

        That address only works while the playground runs: afterwards remove the
        server with `claude mcp remove se-check`.

        Then ask the agent something like "run audit_database and explain the
        critical findings".

        Add --probe after `mcp` and the agent also gets probe_database, which
        runs the dynamic probe (option 6). Only on local databases.""")


def guide_accept(dsn: str) -> str:
    return textwrap.dedent("""
        Some findings are fine on purpose. Here, "plans are public" on public.plans:
        pricing plans everyone may read. Record that, with the reason:

          se-check accept permissive-policy public.plans --reason "Pricing is public."

        permissive-policy and public.plans come from the report: the check is in
        [brackets], next to the object. The reason is mandatory: it is how the next
        person learns why.

        This writes se-check.toml next to the supabase/ folder (commit it). From then
        on the finding leaves the list and stops failing CI, but the report still
        shows it under "Accepted", with the reason. If the problem disappears, the
        report tells you to remove the entry.""")


# Menu entries that run se-check: key -> (label, se-check arguments).
COMMANDS: dict[str, tuple[str, list[str]]] = {
    "1": ("Audit the example database", ["audit"]),
    "2": ("Same, showing only critical and high findings", ["audit", "--min-severity", "high"]),
    "3": ("Same, as JSON (what an AI agent gets over MCP)", ["audit", "--format", "json"]),
    "4": ("List the checks se-check runs", ["checks"]),
    "5": ("Also try the holes: the dynamic probe", ["audit", "--probe"]),
}

# Menu entries that explain something: key -> (label, text builder).
GUIDES: dict[str, tuple[str, Callable[[str], str]]] = {
    "6": ("What does the dynamic probe do?", guide_probe),
    "7": ("What do the parts of a command mean?", guide_command_parts),
    "8": ("How do I run the commands myself?", guide_run_yourself),
    "9": ("How do I audit my own database?", guide_own_database),
    "10": ("How do I connect it to an AI agent (MCP)?", guide_ai_agent),
    "11": ("A finding is fine on purpose: how do I say so?", guide_accept),
}


def menu() -> str:
    lines = ["", "What would you like to do?", "", "  Run se-check on the example"]
    lines += [f"    {key}  {label}" for key, (label, _) in COMMANDS.items()]
    lines += ["", "  Learn how it works"]
    lines += [f"    {key}  {label}" for key, (label, _) in GUIDES.items()]
    lines += ["", "    q  Quit (stops and deletes the example database)", ""]
    return "\n".join(lines)


def run_se_check(args: list[str], dsn: str) -> None:
    print(f"\n$ uv run se-check {' '.join(args)}\n", flush=True)
    result = subprocess.run(
        [sys.executable, "-m", "se_check", *args],
        env={**os.environ, "SE_CHECK_DSN": dsn},
        check=False,
    )
    if args[0] == "audit" and result.returncode == 1:
        print("\n(Exit status 1: there are high or critical findings. In CI this fails the build.)")


def menu_loop(dsn: str) -> bool:
    """Show the menu until the user quits. False when there is no keyboard to read from."""
    print(banner(dsn))
    while True:
        print(menu())
        try:
            choice = input("Choose an option: ").strip().lower()
        except EOFError:
            return False
        if choice in ("q", "quit", "exit"):
            return True
        if choice in COMMANDS:
            run_se_check(COMMANDS[choice][1], dsn)
        elif choice in GUIDES:
            print(GUIDES[choice][1](dsn))
        else:
            first, *_, last = [*COMMANDS, *GUIDES]
            print(f"\n{choice!r} is not in the menu: type a number from {first} to {last}, or q.")
            continue
        try:
            input("\nPress Enter to go back to the menu... ")
        except EOFError:
            return False


def _stop(signum: int, frame: object) -> None:
    raise KeyboardInterrupt


def main() -> None:
    # The Postgres server outlives this process unless it is stopped explicitly, so treat
    # "terminal closed" and "kill" like Ctrl+C and clean up.
    signal.signal(signal.SIGTERM, _stop)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, _stop)

    with tempfile.TemporaryDirectory(prefix="se-check-playground-") as data_dir:
        print("Starting the example database...", flush=True)
        server = pgserver.get_server(data_dir, cleanup_mode="stop")
        dsn = server.get_uri()
        try:
            with psycopg.connect(dsn, autocommit=True) as conn:
                for path in sorted(EXAMPLE_DIR.glob("*.sql")):
                    conn.execute(path.read_text())
            if not menu_loop(dsn):
                # No keyboard (e.g. started in the background): keep serving until stopped.
                print(
                    f"\nNo keyboard input. The database keeps running at\n  {dsn}\n"
                    "until you press Ctrl+C.",
                    flush=True,
                )
                while True:
                    time.sleep(3600)
        except KeyboardInterrupt:
            pass
        finally:
            print("\nStopping and deleting the example database.", flush=True)
            server.cleanup()


if __name__ == "__main__":
    main()
