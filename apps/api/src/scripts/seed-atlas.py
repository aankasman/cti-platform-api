#!/usr/bin/env python3
"""
MITRE ATLAS Seeder
Downloads ATLAS.yaml from GitHub and populates atlas_* tables.

Usage: python3 seed-atlas.py
"""

import json
import os
import subprocess
import sys

try:
    import yaml
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyyaml", "-q"])
    import yaml

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "psycopg2-binary", "-q"])
    import psycopg2
    import psycopg2.extras


# ── Config ──
DB_URL = os.environ.get("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/rinjani_v3")
ATLAS_YAML_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml"
LOCAL_CACHE = "/tmp/ATLAS.yaml"


def download_atlas_yaml():
    """Download ATLAS.yaml from GitHub (or use cached copy)."""
    if os.path.exists(LOCAL_CACHE):
        print(f"  Using cached {LOCAL_CACHE}")
    else:
        import urllib.request
        print(f"  Downloading from {ATLAS_YAML_URL}...")
        urllib.request.urlretrieve(ATLAS_YAML_URL, LOCAL_CACHE)

    with open(LOCAL_CACHE) as f:
        return yaml.safe_load(f)


def connect_db():
    """Connect to PostgreSQL."""
    return psycopg2.connect(DB_URL)


def seed_tactics(conn, tactics):
    """Seed atlas_tactics table."""
    print(f"\n  Seeding {len(tactics)} tactics...")

    cur = conn.cursor()
    for t in tactics:
        atlas_id = t.get("id", "")
        name = t.get("name", "")
        desc = t.get("description", "")
        attack_ref = t.get("ATT&CK-reference", {})
        attack_ref_id = attack_ref.get("id", None) if isinstance(attack_ref, dict) else None
        attack_ref_url = attack_ref.get("url", None) if isinstance(attack_ref, dict) else None
        url = f"https://atlas.mitre.org/tactics/{atlas_id}"

        cur.execute("""
            INSERT INTO atlas_tactics (atlas_id, name, description, attack_reference_id, attack_reference_url, url)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (atlas_id) DO UPDATE SET
                name = EXCLUDED.name,
                description = EXCLUDED.description,
                attack_reference_id = EXCLUDED.attack_reference_id,
                attack_reference_url = EXCLUDED.attack_reference_url,
                updated_at = NOW()
        """, (atlas_id, name, desc, attack_ref_id, attack_ref_url, url))

    conn.commit()
    print(f"  ✓ {len(tactics)} tactics seeded")


def seed_techniques(conn, techniques):
    """Seed atlas_techniques table."""
    print(f"\n  Seeding {len(techniques)} techniques...")

    cur = conn.cursor()
    count = 0
    for t in techniques:
        atlas_id = t.get("id", "")
        name = t.get("name", "")
        desc = t.get("description", "")
        maturity = t.get("maturity", "")
        subtechnique_of = t.get("subtechnique-of", None)
        tactic_ids = json.dumps(t.get("tactics", []))
        attack_ref = t.get("ATT&CK-reference", {})
        attack_ref_id = attack_ref.get("id", None) if isinstance(attack_ref, dict) else None
        attack_ref_url = attack_ref.get("url", None) if isinstance(attack_ref, dict) else None
        url = f"https://atlas.mitre.org/techniques/{atlas_id}"

        cur.execute("""
            INSERT INTO atlas_techniques
                (atlas_id, name, description, maturity, subtechnique_of,
                 tactic_ids, attack_reference_id, attack_reference_url, url)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (atlas_id) DO UPDATE SET
                name = EXCLUDED.name,
                description = EXCLUDED.description,
                maturity = EXCLUDED.maturity,
                subtechnique_of = EXCLUDED.subtechnique_of,
                tactic_ids = EXCLUDED.tactic_ids,
                attack_reference_id = EXCLUDED.attack_reference_id,
                attack_reference_url = EXCLUDED.attack_reference_url,
                updated_at = NOW()
        """, (atlas_id, name, desc, maturity, subtechnique_of,
              tactic_ids, attack_ref_id, attack_ref_url, url))
        count += 1

    conn.commit()
    print(f"  ✓ {count} techniques seeded")


def seed_mitigations(conn, mitigations):
    """Seed atlas_mitigations table."""
    print(f"\n  Seeding {len(mitigations)} mitigations...")

    cur = conn.cursor()
    count = 0
    for m in mitigations:
        atlas_id = m.get("id", "")
        name = m.get("name", "")
        desc = m.get("description", "")
        # Extract technique IDs from the techniques list (each entry has {id, use})
        raw_techs = m.get("techniques", [])
        tech_ids = []
        for t in raw_techs:
            if isinstance(t, dict):
                tech_ids.append(t.get("id", ""))
            elif isinstance(t, str):
                tech_ids.append(t)
        technique_ids = json.dumps(tech_ids)
        ml_lifecycle = json.dumps(m.get("ml-lifecycle", []))
        category = json.dumps(m.get("category", []))
        url = f"https://atlas.mitre.org/mitigations/{atlas_id}"

        cur.execute("""
            INSERT INTO atlas_mitigations
                (atlas_id, name, description, technique_ids, ml_lifecycle, category, url)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (atlas_id) DO UPDATE SET
                name = EXCLUDED.name,
                description = EXCLUDED.description,
                technique_ids = EXCLUDED.technique_ids,
                ml_lifecycle = EXCLUDED.ml_lifecycle,
                category = EXCLUDED.category,
                updated_at = NOW()
        """, (atlas_id, name, desc, technique_ids, ml_lifecycle, category, url))
        count += 1

    conn.commit()
    print(f"  ✓ {count} mitigations seeded")


def seed_case_studies(conn, case_studies):
    """Seed atlas_case_studies table."""
    print(f"\n  Seeding {len(case_studies)} case studies...")

    cur = conn.cursor()
    count = 0
    for cs in case_studies:
        atlas_id = cs.get("id", "")
        name = cs.get("name", "")
        summary = cs.get("summary", "")
        incident_date = cs.get("incident-date", "")
        reporter = cs.get("reporter", "")
        target = cs.get("target", "")
        actor = cs.get("actor", "")

        # Extract technique IDs from procedure steps
        procedure = cs.get("procedure", [])
        procedure_steps = []
        technique_ids = []
        for step in (procedure or []):
            if isinstance(step, dict):
                tech_id = step.get("technique", "")
                tactic = step.get("tactic", "")
                desc = step.get("description", "")
                if tech_id:
                    technique_ids.append(tech_id)
                procedure_steps.append({
                    "tactic": tactic,
                    "technique": tech_id,
                    "description": desc,
                })

        references = cs.get("references", [])
        ref_list = []
        for r in (references or []):
            if isinstance(r, dict):
                ref_list.append({"url": r.get("url", ""), "title": r.get("title", "")})
            elif isinstance(r, str):
                ref_list.append({"url": r, "title": ""})

        url = f"https://atlas.mitre.org/studies/{atlas_id}"

        cur.execute("""
            INSERT INTO atlas_case_studies
                (atlas_id, name, summary, incident_date, reporter, target, actor,
                 technique_ids, procedure_steps, "references", url)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (atlas_id) DO UPDATE SET
                name = EXCLUDED.name,
                summary = EXCLUDED.summary,
                incident_date = EXCLUDED.incident_date,
                reporter = EXCLUDED.reporter,
                target = EXCLUDED.target,
                actor = EXCLUDED.actor,
                technique_ids = EXCLUDED.technique_ids,
                procedure_steps = EXCLUDED.procedure_steps,
                "references" = EXCLUDED."references",
                updated_at = NOW()
        """, (atlas_id, name, summary, incident_date, reporter, target, actor,
              json.dumps(technique_ids), json.dumps(procedure_steps),
              json.dumps(ref_list), url))
        count += 1

    conn.commit()
    print(f"  ✓ {count} case studies seeded")


def main():
    print("╔══════════════════════════════════════════╗")
    print("║   MITRE ATLAS Seeder                     ║")
    print("║   AI/ML Adversarial Threat Landscape      ║")
    print("╚══════════════════════════════════════════╝")

    # Download data
    print("\n[1/6] Loading ATLAS data...")
    data = download_atlas_yaml()
    print(f"  ✓ Loaded: {data.get('name', 'unknown')} v{data.get('version', '?')}")

    # Navigate to the matrix data
    matrices = data.get("matrices", [])
    if not matrices:
        print("  ✗ No matrices found in ATLAS data!")
        sys.exit(1)

    matrix = matrices[0]
    tactics = matrix.get("tactics", [])
    techniques = matrix.get("techniques", [])
    mitigations = matrix.get("mitigations", [])
    case_studies = data.get("case-studies", [])

    print(f"  Found: {len(tactics)} tactics, {len(techniques)} techniques, "
          f"{len(mitigations)} mitigations, {len(case_studies)} case studies")

    # Connect
    print("\n[2/6] Connecting to database...")
    conn = connect_db()
    print("  ✓ Connected")

    # Seed
    print("\n[3/6] Seeding tactics...")
    seed_tactics(conn, tactics)

    print("\n[4/6] Seeding techniques...")
    seed_techniques(conn, techniques)

    print("\n[5/6] Seeding mitigations...")
    seed_mitigations(conn, mitigations)

    print("\n[6/6] Seeding case studies...")
    seed_case_studies(conn, case_studies)

    # Summary
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM atlas_tactics")
    t_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM atlas_techniques")
    tech_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM atlas_mitigations")
    m_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM atlas_case_studies")
    cs_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM atlas_techniques WHERE subtechnique_of IS NOT NULL")
    sub_count = cur.fetchone()[0]

    print(f"\n{'='*44}")
    print(f"  Summary:")
    print(f"    atlas_tactics:         {t_count:>4}")
    print(f"    atlas_techniques:      {tech_count:>4} ({sub_count} sub-techniques)")
    print(f"    atlas_mitigations:     {m_count:>4}")
    print(f"    atlas_case_studies:    {cs_count:>4}")
    print(f"{'='*44}")
    print("  ✅ ATLAS data seeded successfully!")

    conn.close()


if __name__ == "__main__":
    main()
