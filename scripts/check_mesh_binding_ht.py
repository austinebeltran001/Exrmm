#!/usr/bin/env python3
"""Compare portal_meshes / MeshCentral meshes against the mesh ID embedded in an agent.

Read-only diagnostic used to confirm whether an agent is targeting a mesh that
still exists on the MeshCentral server.
"""
import base64
import json
import sqlite3
import sys
import os

PORTAL_DB = "/home/ubuntu/hackertreats-portal/backend/data/portal.db"
MC_DB = "/tmp/ht_mc.db"


def b64_to_hex_meshid(meshid):
    """MeshCentral mesh ids look like 'mesh//<base64url of 48 bytes>'."""
    try:
        tail = meshid.split("//", 1)[1]
    except IndexError:
        return None
    tail = tail.replace("$", "+").replace("@", "/")
    pad = "=" * (-len(tail) % 4)
    try:
        raw = base64.b64decode(tail + pad, validate=False)
    except Exception:
        return None
    return "0x" + raw.hex().upper()


def load_nedb(path, collection=None):
    docs = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                doc = json.loads(line)
            except Exception:
                continue
            if collection and doc.get("_id", "").split("/")[0] != collection:
                continue
            docs.append(doc)
    return docs


def main():
    agent_mesh_hex = sys.argv[1].upper() if len(sys.argv) > 1 else None

    print("=== portal_meshes (portal SQLite) ===")
    con = sqlite3.connect(f"file:{PORTAL_DB}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    rows = con.execute("SELECT * FROM portal_meshes").fetchall()
    portal_map = {}
    for row in rows:
        d = dict(row)
        mid = d.get("meshid", "")
        hexid = b64_to_hex_meshid(mid)
        portal_map[hexid] = d
        print(f"  id={d.get('id')} name={d.get('name')!r} meshid={mid}")
        print(f"    hex={hexid} created={d.get('created_at')}")
    con.close()

    print("\n=== MeshCentral meshes (NeDB) ===")
    mc_map = {}
    for doc in load_nedb(MC_DB, "mesh"):
        mid = doc.get("_id", "")
        hexid = b64_to_hex_meshid(mid)
        mc_map[hexid] = doc
        print(f"  _id={mid}")
        print(f"    hex={hexid} name={doc.get('name')!r} type={doc.get('mtype')} deleted={doc.get('deleted')}")

    print("\n=== MeshCentral nodes (NeDB) ===")
    for doc in load_nedb(MC_DB, "node"):
        print(f"  _id={doc.get('_id')} name={doc.get('name')!r} mesh={doc.get('meshid')}")
        print(f"    conn={doc.get('conn')} lastconnect={doc.get('lastconnecttime')} os={doc.get('osdesc')}")

    if agent_mesh_hex:
        print("\n=== Verdict ===")
        print(f"  agent mesh id     : {agent_mesh_hex}")
        print(f"  exists in Meshes  : {agent_mesh_hex in mc_map}")
        print(f"  exists in portal  : {agent_mesh_hex in portal_map}")
        if agent_mesh_hex in mc_map:
            print(f"  mesh name         : {mc_map[agent_mesh_hex].get('name')!r}")


if __name__ == "__main__":
    main()
