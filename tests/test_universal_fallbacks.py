import os
import tempfile
import unittest

from intelligence.analyzer import analyze_file
from intelligence.dependency_graph import build_dependency_graph
from intelligence.file_profile import FileProfile
from intelligence.models import FileAnalysis, RepoIntelligence
from intelligence.query_engine import query_codebase


class TestUniversalFallbacks(unittest.TestCase):
    def test_unknown_file_uses_zero_knowledge_lexical_tier(self):
        with tempfile.TemporaryDirectory() as repo_root:
            path = os.path.join(repo_root, "PaymentGateway.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("PaymentGatewayTimeoutException gateway_timeout\n")

            analysis = analyze_file(path, repo_root)

            self.assertEqual("unknown", analysis.language)
            self.assertEqual("lexical", analysis.analysis_tier)
            self.assertNotIn("paymentgatewaytimeoutexception", analysis.lexical_terms)
            self.assertEqual(2, analysis.lexical_terms["gateway"])
            self.assertEqual(2, analysis.lexical_terms["timeout"])
            self.assertEqual(1, analysis.lexical_terms["exception"])

    def test_structural_ast_fallback_handles_unmapped_csharp_file(self):
        with tempfile.TemporaryDirectory() as repo_root:
            path = os.path.join(repo_root, "Gateway.cs")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(
                    "public class Gateway\n"
                    "{\n"
                    "    public void NotifyPayment() { }\n"
                    "}\n"
                )

            analysis = analyze_file(path, repo_root)

            self.assertEqual("c_sharp", analysis.language)
            self.assertEqual("structural", analysis.analysis_tier)
            self.assertTrue(analysis.symbol_locations)
            kinds = {location.kind for location in analysis.symbol_locations}
            self.assertTrue(kinds & {"structural", "declaration", "assignment", "block"})

    def test_structural_ast_fallback_captures_parse_errors(self):
        with tempfile.TemporaryDirectory() as repo_root:
            path = os.path.join(repo_root, "Broken.cs")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("public class Broken { void Run( { return; }\n")

            analysis = analyze_file(path, repo_root)

            self.assertEqual("structural", analysis.analysis_tier)
            self.assertTrue(analysis.parse_errors)
            self.assertTrue(any(error["kind"] == "ERROR" for error in analysis.parse_errors))

    def test_lexical_fallback_infers_only_relevant_shared_identifier_edges(self):
        intel = RepoIntelligence(
            repo_path="/repo",
            repo_url="",
            file_analyses=[
                FileAnalysis(
                    path="gateway.txt",
                    language="unknown",
                    lines=1,
                    size_bytes=31,
                    analysis_tier="lexical",
                    lexical_terms={"paymentgatewaytimeoutexception": 2},
                ),
                FileAnalysis(
                    path="client.txt",
                    language="unknown",
                    lines=1,
                    size_bytes=31,
                    analysis_tier="lexical",
                    lexical_terms={"paymentgatewaytimeoutexception": 1},
                ),
                FileAnalysis(
                    path="unrelated.txt",
                    language="unknown",
                    lines=1,
                    size_bytes=10,
                    analysis_tier="lexical",
                    lexical_terms={"unrelated": 1},
                ),
            ],
        )

        graph = build_dependency_graph(intel)

        relationships = graph.lexical_relationships("gateway.txt")
        self.assertEqual(["client.txt"], [target for target, _, _ in relationships])
        self.assertEqual(("paymentgatewaytimeoutexception",), relationships[0][2])
        self.assertGreater(relationships[0][1], 0.35)
        self.assertEqual(["gateway.txt"], graph.lexical_dependents("client.txt"))
        self.assertEqual([], graph.lexical_dependents("unrelated.txt"))

    def test_query_codebase_scores_lexical_tier_from_internal_tokens(self):
        env_profile = FileProfile(
            file=".env",
            basename=".env",
            language="unknown",
            lines=3,
            size_bytes=80,
            analysis_tier="lexical",
            lexical_terms={"payment": 1, "gateway": 2, "timeout": 2, "exception": 1},
        )
        docs_profile = FileProfile(
            file="README.md",
            basename="README.md",
            language="unknown",
            lines=10,
            size_bytes=100,
            analysis_tier="lexical",
            lexical_terms={"installation": 1, "guide": 1},
        )
        structural = FileProfile(
            file="pkg/client.py",
            basename="client.py",
            language="python",
            lines=20,
            size_bytes=200,
            analysis_tier="structural",
            functions=["run"],
            classes=["Client"],
        )

        results = query_codebase(
            {
                ".env": env_profile,
                "README.md": docs_profile,
                "pkg/client.py": structural,
            },
            "PaymentGatewayTimeoutException",
        )

        self.assertTrue(results)
        self.assertEqual(".env", results[0].profile.file)
        self.assertTrue(
            any("Lexical terms match" in reason for reason in results[0].match_reasons)
        )
        self.assertNotIn("README.md", [match.profile.file for match in results])


if __name__ == "__main__":
    unittest.main()
