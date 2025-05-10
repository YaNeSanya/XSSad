import re
import click

# ANSI escape sequences for coloring
COLOR_SOURCE = '\033[93m'  # yellow-like
COLOR_SINK = '\033[91m'    # red-like
COLOR_RESET = '\033[0m'

# Patterns to identify data sources and dangerous sinks
SOURCE_PATTERNS = re.compile(
    r"\b(?:document\.(?:cookie|referrer|URL(?:Unencoded)?|baseURI)|"
    r"location\.(?:href|search|hash|pathname)|window\.name|"
    r"history\.(?:pushState|replaceState)(?:local|session)Storage)\b"
)
SINK_PATTERNS = re.compile(
    r"\b(?:eval|Function|set(?:Timeout|Interval|Immediate)|execScript|document\.(?:write|writeln)|"
    r"\w+\.innerHTML|\w+\.textContent|\w+\.src|crypto\.generateCRMFRequest|"
    r"Range\.createContextualFragment)\b"
)

SCRIPT_BLOCK_RE = re.compile(r'(?is)<script[^>]*>(.*?)</script>')


def find_dom_xss(text: str) -> list[str]:
    """
    Scans provided HTML/text for inline <script> blocks,
    highlights sources and sinks, and returns list of annotated lines.
    """
    results = []

    # Extract all inline script contents
    for match in SCRIPT_BLOCK_RE.finditer(text):
        script = match.group(1).splitlines()
        tracked_vars = set()

        for idx, raw_line in enumerate(script, start=1):
            line = raw_line.rstrip()
            annotated = False

            # Detect sources
            for src_match in SOURCE_PATTERNS.finditer(line):
                src = src_match.group()
                # mark and remember variable usage
                line = line.replace(src, f"{COLOR_SOURCE}{src}{COLOR_RESET}")
                annotated = True
                # if variable assignment, track variable name
                var_assign = re.search(r"var\s+([A-Za-z_$][\w$]*)", line)
                if var_assign:
                    tracked_vars.add(var_assign.group(1))

            # Highlight tracked variables
            for var in list(tracked_vars):
                if re.search(rf"\b{re.escape(var)}\b", line):
                    line = re.sub(rf"\b{re.escape(var)}\b",
                                   f"{COLOR_SOURCE}{var}{COLOR_RESET}", line)
                    annotated = True

            # Detect sinks
            for sink_match in SINK_PATTERNS.finditer(raw_line):
                sink = sink_match.group()
                line = line.replace(sink, f"{COLOR_SINK}{sink}{COLOR_RESET}")
                annotated = True

            if annotated:
                # prefix with line number
                results.append(f"{idx:>3}: {line}")

    return results


def report_dom_findings(html: str):
    """
    Runs detection and prints any found DOM-XSS risks.
    """
    findings = find_dom_xss(html)
    if findings:
        click.secho("[DOM XSS] Potential risky code segments detected:", fg="cyan")
        for line in findings:
            click.echo(line)
    else:
        click.secho("[DOM XSS] No issues found.", fg="green")