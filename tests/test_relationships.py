import unittest

from build_relationships import build_relationships


USER = "arn:aws:iam::123456789012:user/demo-user"
GROUP = "arn:aws:iam::123456789012:group/demo-group"
POLICY = "arn:aws:iam::123456789012:policy/demo-policy"


class TestRelationships(unittest.TestCase):
    def make_data(self):
        return {
            "authorization_details": {
                "Policies": [{
                    "Arn": POLICY,
                    "PolicyName": "demo-policy",
                }],
                "UserDetailList": [{
                    "Arn": USER,
                    "UserName": "demo-user",
                    "GroupList": ["demo-group"],
                    "AttachedManagedPolicies": [{
                        "PolicyArn": POLICY,
                        "PolicyName": "demo-policy",
                    }],
                    "PermissionsBoundary": {
                        "PermissionsBoundaryArn": POLICY,
                    },
                }],
                "GroupDetailList": [{
                    "Arn": GROUP,
                    "GroupName": "demo-group",
                    "AttachedManagedPolicies": [{
                        "PolicyArn": POLICY,
                        "PolicyName": "demo-policy",
                    }],
                }],
                "RoleDetailList": [],
            }
        }

    def test_relationship_types_are_distinct(self):
        report = build_relationships(self.make_data())

        edges = {
            (edge["source"], edge["target"], edge["relation"])
            for edge in report["edges"]
        }

        self.assertEqual(
            edges,
            {
                (USER, POLICY, "attached_policy"),
                (USER, POLICY, "permissions_boundary"),
                (USER, GROUP, "member_of"),
                (GROUP, POLICY, "attached_policy"),
            },
        )
        self.assertEqual(report["summary"]["node_count"], 3)
        self.assertEqual(report["summary"]["edge_count"], 4)
        self.assertEqual(report["summary"]["warning_count"], 0)

    def test_repeated_attachment_does_not_duplicate_edge(self):
        data = self.make_data()
        user = data["authorization_details"]["UserDetailList"][0]
        user["AttachedManagedPolicies"].append({
            "PolicyArn": POLICY,
            "PolicyName": "demo-policy",
        })

        report = build_relationships(data)

        self.assertEqual(report["summary"]["edge_count"], 4)

    def test_missing_policy_details_are_marked_as_reference_only(self):
        data = self.make_data()
        data["authorization_details"]["Policies"] = []

        report = build_relationships(data)
        policy_node = next(
            node for node in report["nodes"]
            if node["id"] == POLICY
        )

        self.assertFalse(policy_node["details_collected"])
        self.assertEqual(policy_node["type"], "managed_policy")
        self.assertEqual(report["summary"]["edge_count"], 4)

    def test_missing_group_is_reported_without_inventing_edge(self):
        data = self.make_data()
        data["authorization_details"]["GroupDetailList"] = []

        report = build_relationships(data)

        self.assertEqual(report["summary"]["warning_count"], 1)
        self.assertEqual(
            report["warnings"][0]["target_name"], "demo-group"
        )
        self.assertFalse(
            any(
                edge["relation"] == "member_of"
                for edge in report["edges"]
            )
        )


if __name__ == "__main__":
    unittest.main()