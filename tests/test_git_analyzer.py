import os
import tempfile
import unittest

from git import Actor, Repo

from intelligence.analyzer import get_parser, run_tags_query
from intelligence.git_analyzer import analyze_deployment_diff
from intelligence.models import SymbolLocation


class TestDeploymentDiff(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.repo = Repo.init(self.temp_dir.name)
        self.actor = Actor("Test Author", "test@example.com")

    def tearDown(self):
        self.repo.close()
        self.temp_dir.cleanup()

    def commit_file(self, content: str, message: str):
        path = os.path.join(self.temp_dir.name, "app.py")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        self.repo.index.add(["app.py"])
        return self.repo.index.commit(message, author=self.actor, committer=self.actor)

    def test_deployment_diff_matches_only_overlapping_target_symbols(self):
        stable = self.commit_file(
            "def stable():\n    return 1\n\ndef unrelated():\n    return 2\n",
            "stable deployment",
        )
        target = self.commit_file(
            "def stable():\n    return 10\n\ndef unrelated():\n    return 2\n",
            "target deployment",
        )

        report = analyze_deployment_diff(self.temp_dir.name, target.hexsha, stable.hexsha)

        self.assertEqual(target.hexsha, report.target_commit)
        self.assertEqual(stable.hexsha, report.stable_commit)
        self.assertEqual(("app.py",), tuple(file.path for file in report.files))
        self.assertEqual(
            ("stable",),
            tuple(match.symbol.name for match in report.symbol_matches),
        )
        self.assertEqual(SymbolLocation("stable", "function", 1, 2), report.symbol_matches[0].symbol)

    def test_tag_query_uses_standard_definition_capture_contract(self):
        source = b"def target():\n    return 1\n\nclass Example:\n    pass\n"
        locations = run_tags_query(get_parser("python"), "python", source)

        self.assertEqual(
            (
                SymbolLocation("target", "function", 1, 2),
                SymbolLocation("Example", "class", 4, 5),
            ),
            tuple(locations),
        )

    def test_deployment_diff_rejects_invalid_commit(self):
        stable = self.commit_file("def stable():\n    return 1\n", "stable deployment")

        with self.assertRaisesRegex(ValueError, "must resolve to repository commits"):
            analyze_deployment_diff(self.temp_dir.name, "does-not-exist", stable.hexsha)


if __name__ == "__main__":
    unittest.main()
