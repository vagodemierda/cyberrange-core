import yaml
from pathlib import Path

SCENARIOS_DIR = Path(__file__).resolve().parents[1] / "scenarios"

def load_scenario(scenario_id: str) -> dict:
    path = SCENARIOS_DIR / f"{scenario_id}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"No existe el escenario: {path}")
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Escenario inválido o vacío: {path}")
    return data

def list_scenarios() -> list[dict]:
    scenarios = []
    for path in SCENARIOS_DIR.glob("*.yaml"):
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            continue
        sid = data.get("id")
        name = data.get("name")
        if sid and name:
            scenarios.append({"id": sid, "name": name})
    return sorted(scenarios, key=lambda x: x["id"])
