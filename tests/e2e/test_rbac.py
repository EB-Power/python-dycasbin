import unittest

import boto3
import casbin

from python_dycasbin import adapter


class TestRBAC(unittest.TestCase):
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

    def test_add_and_get_roles_for_user(self):
        self.e.add_role_for_user("test_add_and_get_roles_for_user", "data_admin")
        result = self.e.get_roles_for_user("test_add_and_get_roles_for_user")
        self.assertListEqual(["data_admin"], result)

    def test_get_users_for_role(self):
        self.e.add_role_for_user("test_get_users_for_role", "data_admin")
        result = self.e.get_users_for_role("data_admin")
        self.assertIn("test_get_users_for_role", result)

    def test_has_role_for_user(self):
        self.e.add_role_for_user("test_has_role_for_user1", "data_admin")
        result = self.e.has_role_for_user("test_has_role_for_user1", "data_admin")
        self.assertTrue(result)
        result = self.e.has_role_for_user("test_has_role_for_user2", "data_admin")
        self.assertFalse(result)

    def test_delete_role_for_user(self):
        self.e.add_role_for_user("test_delete_role_for_user", "data_admin")
        result = self.e.delete_role_for_user("test_delete_role_for_user", "data_admin")
        self.assertTrue(result)

    def test_delete_roles_for_user(self):
        self.e.add_role_for_user("test_delete_roles_for_user", "data_admin")
        result = self.e.delete_roles_for_user("test_delete_roles_for_user")
        self.assertIsNot(False, result)
        self.assertIn(["test_delete_roles_for_user", "data_admin"], result)  # type: ignore
        result = self.e.has_role_for_user("test_delete_roles_for_user", "data_admin")
        self.assertFalse(result)

    def test_delete_user(self):
        self.e.add_role_for_user("test_delete_user", "data_admin")
        result = self.e.has_role_for_user("test_delete_user", "data_admin")
        self.assertTrue(result)
        result = self.e.delete_user("test_delete_user")
        self.assertTrue(result)
        result = self.e.has_role_for_user("test_delete_user", "data_admin")
        self.assertFalse(result)

    def test_delete_role(self):
        self.e.add_role_for_user("test_delete_role", "delete_role")
        result = self.e.has_role_for_user("test_delete_role", "delete_role")
        self.assertTrue(result)
        result = self.e.delete_role("delete_role")
        self.assertTrue(result)
        result = self.e.has_role_for_user("test_delete_role", "delete_role")
        self.assertFalse(result)

    def test_add_permission_for_user_case1(self):
        self.e.add_permission_for_user("test_add_permission_for_user_case1", "read")
        result = self.e.has_permission_for_user(
            "test_add_permission_for_user_case1", "read"
        )
        self.assertTrue(result)

    def test_delete_permission(self):
        self.e.add_permission_for_user("test_delete_permission", "read")
        result = self.e.delete_permission("read")
        self.assertTrue(result)
        result = self.e.has_permission_for_user("test_delete_permission", "read")
        self.assertFalse(result)

    def test_add_permission_for_user_case2(self):
        self.e.add_permission_for_user("test_add_permission_for_user_case2", "write")
        result = self.e.has_permission_for_user(
            "test_add_permission_for_user_case2", "write"
        )
        self.assertTrue(result)
        result = self.e.has_permission_for_user(
            "test_add_permission_for_user_case2", "read"
        )
        self.assertFalse(result)

    def test_delete_permissions_for_user_case1(self):
        self.e.add_permission_for_user(
            "test_delete_permissions_for_user_case1", "write"
        )
        self.e.add_permission_for_user("test_delete_permissions_for_user_case1", "read")
        result = self.e.delete_permissions_for_user(
            "test_delete_permissions_for_user_case1"
        )
        self.assertTrue(result)
        result = self.e.has_permission_for_user(
            "test_delete_permissions_for_user_case1", "write"
        )
        self.assertFalse(result)
        result = self.e.has_permission_for_user(
            "test_delete_permissions_for_user_case1", "read"
        )
        self.assertFalse(result)

    def test_delete_permissions_for_user_case2(self):
        self.e.add_permission_for_user(
            "test_delete_permissions_for_user_case2", "write"
        )
        self.e.add_permission_for_user("test_delete_permissions_for_user_case2", "read")
        result = self.e.get_permissions_for_user(
            "test_delete_permissions_for_user_case2"
        )
        self.assertIn(["test_delete_permissions_for_user_case2", "write"], result)
        self.assertIn(["test_delete_permissions_for_user_case2", "read"], result)

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
