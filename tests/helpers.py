from pathlib import Path

DATA = Path(__file__).parent / "data"


def sample(name: str) -> str:
    return (DATA / name).read_text(encoding="utf-8")
