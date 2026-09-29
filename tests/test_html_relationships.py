import unittest

from html_relationships import render_relationships


class TestHtmlRelationships(unittest.TestCase):
    def make_report(self):
        return {
            "collected_at": "2026-09-29T00:00:00+00:00",
            "nodes": [
                {
                    "id": "demo-user",
                    "type": "user",
                    "name": "테스트 사용자",
                    "details_collected": True,
                },
                {
                    "id": "demo-policy",
                    "type": "managed_policy",
                    "name": "테스트 정책",
                    "details_collected": True,
                },
            ],
            "edges": [
                {
                    "source": "demo-user",
                    "target": "demo-policy",
                    "relation": "attached_policy",
                },
                {
                    "source": "demo-user",
                    "target": "demo-policy",
                    "relation": "permissions_boundary",
                },
            ],
            "warnings": [],
            "limitations": ["실제 유효 권한을 계산하지 않습니다."],
        }

    def test_graph_and_relationship_types_are_displayed(self):
        html = render_relationships(self.make_report())

        self.assertIn("<svg", html)
        self.assertIn("테스트 사용자", html)
        self.assertIn("테스트 정책", html)
        self.assertIn("노드 2개 · 연결 2개", html)
        self.assertIn("정책 연결", html)
        self.assertIn("권한 경계", html)
        self.assertIn('stroke-dasharray="7 5"', html)
        self.assertIn('marker-end="url(#attached_policy)"', html)
        self.assertIn('marker-end="url(#permissions_boundary)"', html)

    def test_untrusted_text_is_escaped(self):
        report = self.make_report()
        payload = '<script>alert("테스트")</script>'

        report["nodes"][0]["name"] = payload
        report["nodes"][0]["id"] = payload

        for edge in report["edges"]:
            edge["source"] = payload

        report["warnings"] = [{
            "target_name": payload,
            "reason": payload,
        }]
        report["limitations"] = [payload]
        report["collected_at"] = payload

        html = render_relationships(report)

        self.assertNotIn(payload, html)
        self.assertNotIn("<script>", html)
        self.assertIn(
            "&lt;script&gt;alert(&quot;테스트&quot;)&lt;/script&gt;",
            html,
        )

    def test_missing_target_node_is_rejected(self):
        report = self.make_report()
        report["edges"][0]["target"] = "missing-node"

        with self.assertRaisesRegex(ValueError, "연결 대상 노드"):
            render_relationships(report)


if __name__ == "__main__":
    unittest.main()