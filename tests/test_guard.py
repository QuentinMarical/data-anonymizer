"""Tests du garde local. Lancer : python -m unittest discover -s tests

Toutes les valeurs sont fictives. Le projet de test est créé dans un dossier temporaire.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
HOOK = SCRIPTS / "guard_hook.py"
ANON = SCRIPTS / "anonymize.py"
SKILL_MD = Path(__file__).resolve().parent.parent / "SKILL.md"
sys.path.insert(0, str(SCRIPTS))
import toggle as T  # noqa: E402

TERMS = """Client Durand SA
deny-path:secrets/*
"""


def run_hook(cwd, tool, tool_input):
    payload = {"cwd": str(cwd), "tool_name": tool, "tool_input": tool_input}
    out = subprocess.run([sys.executable, str(HOOK), "pre"],
                         input=json.dumps(payload).encode(), capture_output=True)
    if out.returncode != 0:
        raise AssertionError(out.stderr.decode(errors="replace"))
    text = out.stdout.decode(errors="replace").strip()
    if not text:
        return "ALLOW"
    return "DENY" if json.loads(text)["hookSpecificOutput"]["permissionDecision"] == "deny" else "ALLOW"


class GuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls._tmp.name)
        (cls.root / ".anonymizer").mkdir()
        (cls.root / ".anonymizer" / "terms.txt").write_text(TERMS, encoding="utf-8")
        (cls.root / "src").mkdir()
        (cls.root / "src" / "conf.py").write_text(
            'API = "http://srv-app01:8080/api"\nOWNER = "Client Durand SA"\n', encoding="utf-8")
        (cls.root / "src" / "clean.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
        (cls.root / "secrets").mkdir()
        (cls.root / "secrets" / "a.txt").write_text("rien\n", encoding="utf-8")
        (cls.root / "Client Durand SA - audit.csv").write_text("x", encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def check(self, expected, tool, tool_input):
        self.assertEqual(run_hook(self.root, tool, tool_input), expected, (tool, tool_input))

    # --- légitimes
    def test_commandes_de_developpement(self):
        for cmd in ["pytest -q", "npm run build", "git status", "git rev-parse HEAD",
                    'git commit -m "type de données, more info"', "find . -type f",
                    'echo "voir .anonymizer/terms.txt"', "cd src && pytest -q"]:
            with self.subTest(cmd=cmd):
                self.check("ALLOW", "Bash", {"command": cmd})

    def test_heredoc_avec_mots_reserves(self):
        self.check("ALLOW", "Bash", {"command": "python x.py <<'EOF'\nfind type here\nEOF"})

    def test_lecture_masquee_par_pipe(self):
        cmd = f"cat src/clean.py | python {ANON} mask -"
        self.check("ALLOW", "Bash", {"command": cmd})

    def test_skill_elle_meme(self):
        self.check("ALLOW", "Read", {"file_path": str(SKILL_MD)})

    def test_glob_sans_noms_sensibles(self):
        self.check("ALLOW", "Glob", {"pattern": "src/*.py"})

    def test_ecriture_d_alias(self):
        self.check("ALLOW", "Write", {"file_path": str(self.root / "new.txt"),
                                      "content": "Client __ANON_TERM_001__ joint à __ANON_EMAIL_001__"})

    # --- à bloquer
    def test_lecture_directe(self):
        self.check("DENY", "Bash", {"command": "cat src/conf.py"})
        self.check("DENY", "Read", {"file_path": "src/conf.py"})

    def test_chainage_apres_masquage(self):
        cmd = f"cat src/conf.py | python {ANON} mask - && cat src/conf.py"
        self.check("DENY", "Bash", {"command": cmd})

    def test_interpreteur_et_jq(self):
        self.check("DENY", "Bash", {"command": "python -c \"print(open('src/conf.py').read())\""})
        self.check("DENY", "Bash", {"command": "jq . src/conf.py"})

    def test_table_d_alias(self):
        self.check("DENY", "Bash", {"command": "cat .anonymizer/mapping.json"})
        self.check("DENY", "Read", {"file_path": ".anonymizer/mapping.json"})

    def test_glob_nom_sensible(self):
        self.check("DENY", "Glob", {"pattern": "*audit*"})

    def test_glob_recursif_avec_nom_sensible(self):
        self.check("DENY", "Glob", {"pattern": "**/*"})

    def test_glob_deny_path(self):
        self.check("DENY", "Glob", {"pattern": "secrets/*"})

    def test_ecriture_en_clair(self):
        self.check("DENY", "Write", {"file_path": str(self.root / "leak.txt"),
                                     "content": "contact jean.dupont@exemple.fr"})

    def test_ecrasement_d_un_fichier_sensible(self):
        self.check("DENY", "Write", {"file_path": str(self.root / "src" / "conf.py"),
                                     "content": "__ANON_HOST_001__"})
        self.check("DENY", "Edit", {"file_path": str(self.root / "src" / "conf.py"),
                                    "old_string": "a", "new_string": "b"})

    def test_ecriture_table_d_alias(self):
        self.check("DENY", "Write", {"file_path": str(self.root / ".anonymizer" / "mapping.json"),
                                     "content": "{}"})


class ToggleTests(unittest.TestCase):
    """Fusion de .claude/settings.local.json : on et off ne touchent qu'au garde."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.proj = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write_settings(self, data):
        path = T.settings_path(self.proj)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")

    def read_settings(self):
        return json.loads(T.settings_path(self.proj).read_text(encoding="utf-8"))

    def other_hooks(self):
        return {
            "PostToolUse": [{"matcher": "Write|Edit",
                             "hooks": [{"type": "command", "command": "prettier --write x"}]}],
            "PreToolUse": [{"matcher": "Bash",
                            "hooks": [{"type": "command", "command": "echo mine"}]}],
        }

    def test_on_cree_les_hooks_et_le_fichier_de_termes(self):
        T.enable(self.proj)
        self.assertTrue(T.is_active(self.proj))
        self.assertIn("UserPromptSubmit", self.read_settings()["hooks"])
        self.assertTrue((self.proj / ".anonymizer" / "terms.txt").exists())
        self.assertTrue((self.proj / ".anonymizer" / ".gitignore").exists())

    def test_on_pointe_vers_le_script_absolu(self):
        T.enable(self.proj)
        self.assertIn(T.GUARD.resolve().as_posix(), json.dumps(self.read_settings()))

    def test_on_preserve_hooks_et_permissions(self):
        self.write_settings({"permissions": {"allow": ["Bash(git *)"]}, "hooks": self.other_hooks()})
        T.enable(self.proj)
        data = self.read_settings()
        self.assertEqual(data["permissions"], {"allow": ["Bash(git *)"]})
        self.assertIn(self.other_hooks()["PostToolUse"][0], data["hooks"]["PostToolUse"])
        self.assertIn(self.other_hooks()["PreToolUse"][0], data["hooks"]["PreToolUse"])
        self.assertEqual(len(data["hooks"]["PreToolUse"]), 2)   # le hook existant + le garde

    def test_on_est_idempotent(self):
        T.enable(self.proj)
        first = self.read_settings()
        T.enable(self.proj)
        self.assertEqual(self.read_settings(), first)

    def test_off_retire_seulement_le_garde(self):
        self.write_settings({"permissions": {"allow": ["Read"]}, "hooks": self.other_hooks()})
        T.enable(self.proj)
        T.disable(self.proj)
        self.assertEqual(self.read_settings(),
                         {"permissions": {"allow": ["Read"]}, "hooks": self.other_hooks()})

    def test_off_nettoie_les_cles_vides(self):
        T.enable(self.proj)
        T.disable(self.proj)
        self.assertEqual(self.read_settings(), {})
        self.assertFalse(T.is_active(self.proj))

    def test_off_ne_supprime_pas_la_table_d_alias(self):
        T.enable(self.proj)
        (self.proj / ".anonymizer" / "mapping.json").write_text("{}", encoding="utf-8")
        T.disable(self.proj)
        self.assertTrue((self.proj / ".anonymizer" / "mapping.json").exists())
        self.assertTrue((self.proj / ".anonymizer" / "terms.txt").exists())

    def test_toggle_bascule(self):
        self.assertEqual(T.toggle(self.proj), "on")
        self.assertTrue(T.is_active(self.proj))
        self.assertEqual(T.toggle(self.proj), "off")
        self.assertFalse(T.is_active(self.proj))

    def test_json_invalide_refuse_sans_rien_ecraser(self):
        path = T.settings_path(self.proj)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{pas du json", encoding="utf-8")
        with self.assertRaises(SystemExit):
            T.enable(self.proj)
        self.assertEqual(path.read_text(encoding="utf-8"), "{pas du json")


if __name__ == "__main__":
    unittest.main()
