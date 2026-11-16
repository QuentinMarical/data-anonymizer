"""Tests du serveur MCP (stdio). Lancer : python -m unittest discover -s tests

Projet temporaire et valeurs fictives uniquement.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SERVER = Path(__file__).resolve().parent.parent / "scripts" / "mcp_server.py"


class McpServerTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / ".anonymizer").mkdir()
        (self.root / ".anonymizer" / "terms.txt").write_text("Client Durand SA\n", encoding="utf-8")
        (self.root / "src").mkdir()
        (self.root / "src" / "conf.py").write_text(
            'OWNER = "Client Durand SA"\nAPI = "http://srv-app01:8080/api"\n', encoding="utf-8")
        env = dict(os.environ, CLAUDE_PROJECT_DIR=str(self.root))
        # stderr ignoré : un tube non lu pourrait se remplir et bloquer le serveur
        self.proc = subprocess.Popen([sys.executable, str(SERVER)], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
        self.next_id = 1

    def tearDown(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=10)
        self.proc.stdout.close()
        self._tmp.cleanup()

    def send(self, method, params=None):
        msg = {"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params or {}}
        self.next_id += 1
        self.proc.stdin.write((json.dumps(msg) + "\n").encode("utf-8"))
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            raise AssertionError("le serveur s'est arrêté sans répondre")
        return json.loads(line.decode("utf-8"))

    def tool(self, name, arguments):
        resp = self.send("tools/call", {"name": name, "arguments": arguments})
        return resp["result"]

    def test_initialize_et_outils(self):
        init = self.send("initialize")
        self.assertEqual(init["result"]["serverInfo"]["name"], "data-anonymizer")
        names = [t["name"] for t in self.send("tools/list")["result"]["tools"]]
        self.assertEqual(names, ["scan", "mask", "restore", "alias", "guard_status", "guard_enable"])
        self.assertNotIn("guard_disable", names)

    def test_guard_status_puis_enable(self):
        text = self.tool("guard_status", {})["content"][0]["text"]
        self.assertIn("INACTIF", text)
        enabled = self.tool("guard_enable", {})
        self.assertFalse(enabled["isError"])
        self.assertIn("ACTIF", enabled["content"][0]["text"])
        settings = json.loads((self.root / ".claude" / "settings.local.json").read_text(encoding="utf-8"))
        self.assertIn("guard_hook.py", json.dumps(settings["hooks"]))
        self.assertIn("ACTIF", self.tool("guard_status", {})["content"][0]["text"])
        self.assertNotIn("INACTIF", self.tool("guard_status", {})["content"][0]["text"])

    def test_guard_disable_n_existe_pas(self):
        resp = self.send("tools/call", {"name": "guard_disable", "arguments": {}})
        self.assertEqual(resp["error"]["code"], -32602)

    def test_json_invalide_ne_tue_pas_le_serveur(self):
        settings = self.root / ".claude" / "settings.local.json"
        settings.parent.mkdir(parents=True, exist_ok=True)
        settings.write_text("{pas du json", encoding="utf-8")
        result = self.tool("guard_enable", {})
        self.assertTrue(result["isError"])
        self.assertEqual(settings.read_text(encoding="utf-8"), "{pas du json")
        status = self.tool("guard_status", {})               # le serveur tourne toujours
        self.assertTrue(status["isError"])
        self.assertEqual(settings.read_text(encoding="utf-8"), "{pas du json")

    def test_scan_ne_renvoie_aucune_valeur(self):
        text = self.tool("scan", {"path": "src/conf.py"})["content"][0]["text"]
        self.assertIn("TERM=1", text)
        self.assertNotIn("Client Durand SA", text)

    def test_mask_puis_restore_sans_renvoyer_le_contenu(self):
        masked = self.tool("mask", {"path": "src/conf.py"})
        self.assertFalse(masked["isError"])
        copy = (self.root / ".anonymizer" / "masked" / "src" / "conf.py").read_text(encoding="utf-8")
        self.assertIn("__ANON_TERM_001__", copy)
        self.assertNotIn("Client Durand SA", copy)

        restored = self.tool("restore", {"path": ".anonymizer/masked/src/conf.py",
                                         "output": "out/conf.py"})
        self.assertFalse(restored["isError"])
        self.assertNotIn("Client Durand SA", restored["content"][0]["text"])
        result = (self.root / "out" / "conf.py").read_text(encoding="utf-8")
        self.assertIn("Client Durand SA", result)

    def test_alias_renvoie_seulement_l_alias(self):
        text = self.tool("alias", {"value": "Client Durand SA"})["content"][0]["text"]
        self.assertEqual(text, "Alias : __ANON_TERM_001__")

    def test_chemin_hors_projet_refuse(self):
        result = self.tool("restore", {"path": "src/conf.py", "output": "../evasion.txt"})
        self.assertTrue(result["isError"])

    def test_sortie_ne_peut_pas_ecraser_la_source(self):
        result = self.tool("mask", {"path": "src/conf.py", "output": "src/conf.py"})
        self.assertTrue(result["isError"])
        original = (self.root / "src" / "conf.py").read_text(encoding="utf-8")
        self.assertIn("Client Durand SA", original)

    def test_outil_inconnu(self):
        resp = self.send("tools/call", {"name": "inconnu", "arguments": {}})
        self.assertEqual(resp["error"]["code"], -32602)


if __name__ == "__main__":
    unittest.main()
