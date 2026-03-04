#!/usr/bin/env python3
"""
MITRE FiGHT Seeder
Downloads fight.yaml from GitHub and populates fight_* tables.
Also imports FiGHT threat groups into threat_actors.

Usage: python3 seed-fight.py
"""

import json
import os
import subprocess
import sys
import uuid

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
FIGHT_YAML_URL = "https://raw.githubusercontent.com/mitre/FiGHT/main/fight.yaml"
LOCAL_CACHE = "/tmp/fight.yaml"


def download_fight_yaml():
    """Download fight.yaml from GitHub (or use cached copy)."""
    if os.path.exists(LOCAL_CACHE):
        print(f"  Using cached {LOCAL_CACHE}")
    else:
        import urllib.request
        print(f"  Downloading from {FIGHT_YAML_URL}...")
        urllib.request.urlretrieve(FIGHT_YAML_URL, LOCAL_CACHE)
    
    with open(LOCAL_CACHE) as f:
        return yaml.safe_load(f)


def connect_db():
    """Connect to PostgreSQL."""
    return psycopg2.connect(DB_URL)


def seed_tactics(conn, data):
    """Seed fight_tactics table."""
    tactics = data.get("tactics", [])
    print(f"\n  Seeding {len(tactics)} tactics...")
    
    cur = conn.cursor()
    for t in tactics:
        tactic_id = t.get("id", "")
        name = t.get("name", "")
        desc = t.get("description", "")
        short = t.get("short-name", name.lower().replace(" ", "-"))
        url = f"https://fight.mitre.org/tactics/{tactic_id}"
        
        cur.execute("""
            INSERT INTO fight_tactics (mitre_id, name, description, short_name, url)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (mitre_id) DO UPDATE SET 
                name = EXCLUDED.name,
                description = EXCLUDED.description,
                updated_at = NOW()
        """, (tactic_id, name, desc, short, url))
    
    conn.commit()
    print(f"  ✓ {len(tactics)} tactics seeded")


def seed_techniques(conn, data):
    """Seed fight_techniques table."""
    techniques = data.get("techniques", [])
    print(f"\n  Seeding {len(techniques)} techniques...")
    
    cur = conn.cursor()
    count = 0
    for t in techniques:
        fight_id = t.get("id", "")
        name = t.get("name", "")
        desc = t.get("description", "")
        bluf = t.get("bluf", "")
        status = t.get("status", "")
        arch = t.get("architecture-segment", "")
        typecode = t.get("typecode", "")
        tactic_ids = json.dumps(t.get("tactics", []))
        platforms = json.dumps([])  # FiGHT doesn't have standard platforms
        precond = json.dumps(t.get("preconditions", []))
        postcond = json.dumps(t.get("postconditions", []))
        assets = json.dumps(t.get("criticalassets", []))
        detections = json.dumps(t.get("detections", []))
        procedures = json.dumps(t.get("procedureexamples", []))
        refs = json.dumps(t.get("references", []))
        url = f"https://fight.mitre.org/techniques/{fight_id}"
        
        # Handle addendums (sub-techniques style enhancements)
        addendums = t.get("addendums", [])
        if addendums and isinstance(addendums, list):
            # Merge addendum platforms if present
            all_platforms = set()
            for a in addendums:
                for p in (a.get("platforms", []) or []):
                    all_platforms.add(p)
            if all_platforms:
                platforms = json.dumps(list(all_platforms))
        
        cur.execute("""
            INSERT INTO fight_techniques 
                (fight_id, name, description, bluf, status, architecture_segment,
                 typecode, tactic_ids, platforms, preconditions, postconditions,
                 critical_assets, detections, procedure_examples, "references", url)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (fight_id) DO UPDATE SET 
                name = EXCLUDED.name,
                description = EXCLUDED.description,
                bluf = EXCLUDED.bluf,
                status = EXCLUDED.status,
                architecture_segment = EXCLUDED.architecture_segment,
                tactic_ids = EXCLUDED.tactic_ids,
                platforms = EXCLUDED.platforms,
                preconditions = EXCLUDED.preconditions,
                postconditions = EXCLUDED.postconditions,
                critical_assets = EXCLUDED.critical_assets,
                detections = EXCLUDED.detections,
                procedure_examples = EXCLUDED.procedure_examples,
                "references" = EXCLUDED."references",
                updated_at = NOW()
        """, (fight_id, name, desc, bluf, status, arch, typecode,
              tactic_ids, platforms, precond, postcond, assets,
              detections, procedures, refs, url))
        count += 1
    
    conn.commit()
    print(f"  ✓ {count} techniques seeded")


def seed_mitigations(conn, data):
    """Seed fight_mitigations table."""
    mitigations = data.get("mitigations", [])
    print(f"\n  Seeding {len(mitigations)} mitigations...")
    
    cur = conn.cursor()
    count = 0
    for m in mitigations:
        fight_id = m.get("id", "")
        name = m.get("name", "")
        desc = m.get("description", "")
        tech_ids = json.dumps(m.get("techniques", []))
        url = f"https://fight.mitre.org/mitigations/{fight_id}"
        
        cur.execute("""
            INSERT INTO fight_mitigations (fight_id, name, description, technique_ids, url)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (fight_id) DO UPDATE SET 
                name = EXCLUDED.name,
                description = EXCLUDED.description,
                technique_ids = EXCLUDED.technique_ids,
                updated_at = NOW()
        """, (fight_id, name, desc, tech_ids, url))
        count += 1
    
    conn.commit()
    print(f"  ✓ {count} mitigations seeded")


def seed_groups(conn, data):
    """Import FiGHT groups into threat_actors and create group→technique mappings."""
    groups = data.get("groups", [])
    print(f"\n  Seeding {len(groups)} threat groups...")
    
    cur = conn.cursor()
    group_technique_count = 0
    
    for g in groups:
        group_id = g.get("id", "")
        name = g.get("name", "")
        desc = g.get("description", "")
        aliases = json.dumps(g.get("aliases", []))
        stix_id = f"fight--{group_id}"
        
        # Upsert into threat_actors
        cur.execute("""
            INSERT INTO threat_actors (
                id, stix_id, name, aliases, description,
                primary_motivation, sophistication,
                created_at, updated_at
            ) VALUES (
                gen_random_uuid(), %s, %s, %s, %s,
                'telco-targeting', 'advanced',
                NOW(), NOW()
            )
            ON CONFLICT (stix_id) DO UPDATE SET
                name = EXCLUDED.name,
                description = EXCLUDED.description,
                aliases = EXCLUDED.aliases,
                updated_at = NOW()
            RETURNING id
        """, (stix_id, name, aliases, desc))
        
        actor_row = cur.fetchone()
        actor_id = str(actor_row[0]) if actor_row else group_id
        
        # Create group→technique mappings
        techniques = g.get("techniques", [])
        for t in techniques:
            tech_id = t.get("id", "") if isinstance(t, dict) else str(t)
            tech_name = t.get("name", "") if isinstance(t, dict) else ""
            tech_use = t.get("use", "") if isinstance(t, dict) else ""
            
            cur.execute("""
                INSERT INTO fight_group_techniques 
                    (group_id, group_name, fight_technique_id, technique_name, description)
                VALUES (%s, %s, %s, %s, %s)
            """, (actor_id, name, tech_id, tech_name, tech_use))
            group_technique_count += 1
    
    conn.commit()
    print(f"  ✓ {len(groups)} groups imported into threat_actors")
    print(f"  ✓ {group_technique_count} group→technique mappings created")


def main():
    print("╔══════════════════════════════════════════╗")
    print("║   MITRE FiGHT Seeder                     ║")
    print("║   5G Hierarchy of Threats                 ║")
    print("╚══════════════════════════════════════════╝")
    
    # Download data
    print("\n[1/5] Loading FiGHT data...")
    data = download_fight_yaml()
    print(f"  ✓ Loaded: {data.get('name', 'unknown')}")
    
    # Connect
    print("\n[2/5] Connecting to database...")
    conn = connect_db()
    print("  ✓ Connected")
    
    # Seed
    print("\n[3/5] Seeding tactics...")
    seed_tactics(conn, data)
    
    print("\n[4/5] Seeding techniques & mitigations...")
    seed_techniques(conn, data)
    seed_mitigations(conn, data)
    
    print("\n[5/5] Seeding groups & relationships...")
    seed_groups(conn, data)
    
    # Summary
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM fight_tactics")
    t_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM fight_techniques")
    tech_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM fight_mitigations")
    m_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM fight_group_techniques")
    gt_count = cur.fetchone()[0]
    
    print(f"\n{'='*44}")
    print(f"  Summary:")
    print(f"    fight_tactics:          {t_count:>4}")
    print(f"    fight_techniques:       {tech_count:>4}")
    print(f"    fight_mitigations:      {m_count:>4}")
    print(f"    fight_group_techniques: {gt_count:>4}")
    print(f"{'='*44}")
    print("  ✅ FiGHT data seeded successfully!")
    
    conn.close()


if __name__ == "__main__":
    main()
