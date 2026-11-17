"""Keep mandatory development guidance in the first-read prefix of AGENTS.md."""
from pathlib import Path
import re


def test_development_guidance_fits_in_first_read_prefix() -> None:
    path = Path(__file__).resolve().parents[1] / "AGENTS.md"
    text = path.read_bytes().replace(b"\r\n", b"\n")
    # Repository budget, not a claim about the limits of every agent client.
    prefix_bytes = 16 * 1024
    heading = "### 开发约定".encode()
    starts = list(re.finditer(rb"^" + heading + rb"$", text, re.MULTILINE))
    assert len(starts) == 1, "Expected one early development guidance section"
    match = starts[0]
    next_section = re.search(rb"^## ", text[match.end():], re.MULTILINE)
    assert next_section is not None
    end = match.end() + next_section.start()
    assert end <= prefix_bytes, f"Development guidance ends at byte {end}; budget is {prefix_bytes}"
