import unittest

import boto3
import casbin

from python_dycasbin import adapter


class TestManagement(unittest.TestCase):
    def setUp(self):
        self.table_name = "casbin_rule"
        self.aws_endpoint_url = "http://localhost:8000"
        self.aws_region_name = "us-east-1"
        self.aws_access_key_id = "anything"
        self.aws_secret_access_key = "anything"
        self.aws_use_ssl = False
        self.aws_verify = False

        test_adapter = adapter.Adapter(
            table_name=self.table_name,
            aws_endpoint_url=self.aws_endpoint_url,
            aws_region_name=self.aws_region_name,
            aws_access_key_id=self.aws_access_key_id,
            aws_secret_access_key=self.aws_secret_access_key,
            aws_use_ssl=self.aws_use_ssl,
            aws_verify=self.aws_verify,
        )

        self.e = casbin.Enforcer("tests/e2e/rbac_model.conf", test_adapter)

    def test_add_policy_get_policy(self):
        policy = ["1suuj7Lzff", "data4", "write"]
        self.e.add_policy(*policy)
        self.e.add_policy("1suuj7Lzff", "data4", "write")
        policies = self.e.get_policy()
        self.assertIn(policy, policies)

    def test_enforcer(self):
        self.e.add_policy("vH5A0DLZAl", "data4", "write")
        result_true = self.e.enforce("vH5A0DLZAl", "data4", "write")
        self.assertTrue(result_true)
        result_false = self.e.enforce("vH5A0DLZAl", "data5", "write")
        self.assertFalse(result_false)

    def test_enforce_ex(self):
        result_true = self.e.enforce_ex("OwR8cXikqw", "data4", "write")
        self.assertTrue(result_true)
        result_false = self.e.enforce_ex("OwR8cXikqw", "data5", "write")
        self.assertFalse(result_false[0])

    def test_get_all_subjects(self):
        self.e.add_policy("bBV8kAeTuk", "data5", "read")
        result = self.e.get_all_subjects()
        self.assertIn("bBV8kAeTuk", result)

    def test_get_all_named_subjects(self):
        self.e.add_policy("qw1NGNQOq0", "data5", "read")
        self.e.add_policy("gAZgBkYwyb", "data5", "read")
        self.e.add_policy("y9enHfJMGG", "data5", "read")
        result = self.e.get_all_named_subjects("p")
        self.assertIn("qw1NGNQOq0", result)
        self.assertIn("gAZgBkYwyb", result)
        self.assertIn("y9enHfJMGG", result)

    def test_get_all_objects(self):
        self.e.add_policy("MROaMgeena", "data5", "read")
        result = self.e.get_all_objects()
        self.assertIn("data5", result)

    def test_get_all_named_objects(self):
        self.e.add_policy("FPPcCTJhfg", "new_obj1", "read")
        result = self.e.get_all_named_objects("p")
        self.assertIn("new_obj1", result)

    def test_get_all_actions(self):
        self.e.add_policy("5Ux56gXVjp", "data1", "X7zaTl7kwr")
        self.e.add_policy("5Ux56gXVjp", "data1", "tQIxcrfHvW")
        result = self.e.get_all_actions()
        self.assertIn("X7zaTl7kwr", result)
        self.assertIn("tQIxcrfHvW", result)
        self.assertNotIn("IuTFEeQxIg", result)

    def test_get_all_named_actions(self):
        self.e.add_policy("riyBrhVml6", "data1", "UYQNQCiG8f")
        self.e.add_policy("riyBrhVml6", "data1", "ZJBlXoY03y")
        result = self.e.get_all_named_actions("p")
        self.assertIn("UYQNQCiG8f", result)
        self.assertIn("ZJBlXoY03y", result)
        self.assertNotIn("IuTFEeQxIg", result)

    def test_add_role_for_user(self):
        result = self.e.add_role_for_user("nm8aE7o5HR", "RmqbX5ELvs")
        self.assertTrue(result)

    def test_get_all_roles(self):
        self.e.add_role_for_user("dghSEaQzbS", "CBtqJR6EJw")
        result = self.e.get_all_roles()
        self.assertIn("CBtqJR6EJw", result)

    def test_get_all_named_roles(self):
        self.e.add_role_for_user("mMLyjr3ozn", "WGet7EpgS0")
        result = self.e.get_all_named_roles("g")
        self.assertIn("WGet7EpgS0", result)

    def test_get_filtered_policy(self):
        self.e.add_policy("cb1znyqD7T", "data5", "read")
        result = self.e.get_filtered_policy(0, "cb1znyqD7T")
        self.assertIn(["cb1znyqD7T", "data5", "read"], result)

    def test_get_named_policy(self):
        self.e.add_policy("aPmDWx33SH", "data4", "write")
        self.e.add_policy("mfHM74BXBg", "data5", "read")
        result = self.e.get_named_policy("p")
        self.assertIn(["aPmDWx33SH", "data4", "write"], result)
        self.assertNotIn(["aPmDWx33SH", "data4", "read"], result)
        self.assertIn(["mfHM74BXBg", "data5", "read"], result)
        self.assertNotIn(["mfHM74BXBg", "data4", "read"], result)

    def test_get_filtered_named_policy(self):
        self.e.add_policy("bavADh0Awa", "data4", "write")
        result = self.e.get_filtered_named_policy("p", 0, "bavADh0Awa")
        self.assertIn(["bavADh0Awa", "data4", "write"], result)
        self.assertNotIn(["bavADh0Awa", "data4", "read"], result)

    def test_get_grouping_policy(self):
        self.e.add_grouping_policy("dghSEaQzbS", "admin")
        result = self.e.get_grouping_policy()
        self.assertIn(["dghSEaQzbS", "admin"], result)

    def test_get_filtered_grouping_policy(self):
        self.e.add_grouping_policy("zPhvX3tU77", "admin")
        result = self.e.get_filtered_grouping_policy(0, "zPhvX3tU77")
        self.assertIn(["zPhvX3tU77", "admin"], result)

    def test_get_named_grouping_policy_case1(self):
        self.e.add_grouping_policy("S8v6yInuhY", "admin")
        result = self.e.get_named_grouping_policy("g")
        self.assertIn(["S8v6yInuhY", "admin"], result)

    def test_get_named_grouping_policy_case2(self):
        self.e.add_grouping_policy("7zyYG5fqM9", "admin")
        result = self.e.get_filtered_named_grouping_policy("g", 0, "7zyYG5fqM9")
        self.assertIn(["7zyYG5fqM9", "admin"], result)

    def test_has_policy(self):
        self.e.add_policy("xgt0MQOMen", "data4", "write")
        result = self.e.has_policy("xgt0MQOMen", "data4", "write")
        self.assertTrue(result)
        result = self.e.has_policy("xgt0MQOMen", "data4", "read")
        self.assertFalse(result)

    def test_has_named_policy(self):
        self.e.add_policy("xUhT7Y6JI7", "data4", "write")
        result = self.e.has_named_policy("p", "xUhT7Y6JI7", "data4", "write")
        self.assertTrue(result)
        result = self.e.has_policy("p", "xUhT7Y6JI7", "data4", "read")
        self.assertFalse(result)

    def test_add_named_policy(self):
        result = self.e.add_named_grouping_policy("g", "ilYTMKV6X7", "data_g", "read")
        self.assertTrue(result)

    def test_remove_policy(self):
        self.e.add_policy("urnyBULgF4", "data5", "write")
        self.e.add_policy("urnyBULgF4", "data5", "read")
        result = self.e.remove_policy("urnyBULgF4", "data5", "write")
        self.assertTrue(result)
        result = self.e.get_policy()
        self.assertNotIn(["urnyBULgF4", "data5", "write"], result)
        self.assertIn(["urnyBULgF4", "data5", "read"], result)

    def test_remove_policies_case1(self):
        # Not implemented
        result = self.e.remove_policies("K2IAjeepBh")
        self.assertFalse(result)

    def test_remove_filtered_policy(self):
        self.e.add_policy("e2pMnwUGc1", "data5", "read")
        result = self.e.remove_filtered_policy(0, "e2pMnwUGc1", "data5", "read")
        self.assertTrue(result)
        result = self.e.get_policy()
        self.assertListEqual([], result)

    def test_remove_named_policy(self):
        self.e.add_named_policy("p", "P9vmnUdxqh", "files", "read")
        result = self.e.remove_named_policy("p", "P9vmnUdxqh", "files", "read")
        self.assertTrue(result)
        result = self.e.get_policy()
        self.assertListEqual([], result)

    def test_remove_policies_case2(self):
        # Not implemented
        result = self.e.remove_named_policies("p", "ccnurObEST")
        self.assertFalse(result)

    def test_remove_filtered_named_policy(self):
        self.e.add_named_policy("p", "6XRDpwNsvw", "images", "write")
        result = self.e.remove_filtered_named_policy(
            "p", 0, "6XRDpwNsvw", "images", "write"
        )
        self.assertTrue(result)
        result = self.e.get_policy()
        self.assertListEqual([], result)

    def test_has_grouping_policy(self):
        self.e.add_grouping_policy("FXhT9RBzAo", "admin")
        result = self.e.has_grouping_policy("FXhT9RBzAo", "admin")
        self.assertTrue(result)
        result = self.e.has_grouping_policy("FXhT9RBzAo", "admin2")
        self.assertFalse(result)

    def test_has_named_grouping_policy(self):
        self.e.add_grouping_policy("elnox0bgjh", "admin")
        result = self.e.has_named_grouping_policy("g", "elnox0bgjh", "admin")
        self.assertTrue(result)
        result = self.e.has_named_grouping_policy("g", "elnox0bgjh", "admin2")
        self.assertFalse(result)

    def test_add_grouping_policy(self):
        result = self.e.add_grouping_policy("sHyJP3Yxj8", "data2_admin")
        self.assertTrue(result)
        result = self.e.has_grouping_policy("sHyJP3Yxj8", "data2_admin")
        self.assertTrue(result)

    def test_add_grouping_policies(self):
        # Not implemented
        result = self.e.add_grouping_policies(
            [["jIJv0pqSRr", "data4_admin"], ["eybi6hf6m0", "data5_admin"]]
        )
        self.assertFalse(result)

    def test_remove_grouping_policy(self):
        # Not implemented
        self.e.add_grouping_policy("oLsENrAEom", "data2_admin")
        result = self.e.remove_grouping_policy("oLsENrAEom", "data2_admin")
        self.assertTrue(result)
        result = self.e.has_grouping_policy("oLsENrAEom", "data2_admin")
        self.assertFalse(result)

    def test_remove_grouping_policies(self):
        # Not implemented
        self.e.add_grouping_policy("uFRsrJ2gJe", "data2_admin")
        result = self.e.remove_grouping_policies([["uFRsrJ2gJe", "data2_admin"]])
        self.assertFalse(result)

    def test_remove_filtered_grouping_policy(self):
        result = self.e.remove_filtered_grouping_policy(0, "JsT6BOYJtf")
        self.assertListEqual([], result)

    def test_remove_named_grouping_policies(self):
        self.e.add_grouping_policy("IL8Cvh6sqL", "data4_admin")
        self.e.add_grouping_policy("vVm78hI07v", "data5_admin")
        result = self.e.remove_named_grouping_policies(
            "g", [["IL8Cvh6sqL", "data4_admin"], ["vVm78hI07v", "data5_admin"]]
        )
        self.assertFalse(result)

    def test_remove_named_grouping_policy_case2(self):
        self.e.add_grouping_policy("z1oZ0MWTqW", "data2_admin")
        result = self.e.remove_filtered_named_grouping_policy("g", 0, "z1oZ0MWTqW")
        self.assertIn(["z1oZ0MWTqW", "data2_admin"], result)

    def test_update_policy(self):
        result = self.e.add_policy("oXrsGpXPB6", "files", "read")
        result = self.e.get_policy()
        self.assertIn(["oXrsGpXPB6", "files", "read"], result)
        result = self.e.update_policy(
            ["oXrsGpXPB6", "files", "read"], ["oXrsGpXPB6", "files", "write"]
        )
        self.assertTrue(result)
        result = self.e.get_policy()
        self.assertIn(["oXrsGpXPB6", "files", "write"], result)

    def test_update_policies(self):
        # not implemented
        result = self.e.update_policies(
            ["wr0CBpB99O", "files", "read"], ["wr0CBpB99O", "files", "write"]
        )
        self.assertFalse(result)

    def tearDown(self):
        client = boto3.client(
            "dynamodb",
            endpoint_url=self.aws_endpoint_url,
            region_name=self.aws_region_name,
            aws_access_key_id=self.aws_access_key_id,
            aws_secret_access_key=self.aws_secret_access_key,
            use_ssl=self.aws_use_ssl,
            verify=self.aws_verify,
        )
        client.delete_table(TableName=self.table_name)


if __name__ == "__main__":
    unittest.main()
