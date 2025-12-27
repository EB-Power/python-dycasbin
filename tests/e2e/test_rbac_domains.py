import unittest

import boto3
import casbin

from python_dycasbin import adapter


class TestRBACWithDomains(unittest.TestCase):
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

        self.e = casbin.Enforcer("tests/e2e/rbac_with_domains_model.conf", test_adapter)

    def test_get_users_for_role_in_domain(self):
        self.e.add_role_for_user_in_domain(
            "test_user1_domain1", "data_admin", "domain1"
        )
        self.e.add_role_for_user_in_domain(
            "test_user2_domain1", "data2_admin", "domain1"
        )
        self.e.add_role_for_user_in_domain(
            "test_user3_domain1", "data2_admin", "domain1"
        )
        self.e.add_role_for_user_in_domain(
            "test_user1_domain2", "data2_admin", "domain2"
        )
        domain1_result = self.e.get_users_for_role_in_domain("data2_admin", "domain1")
        self.assertNotIn("test_user1_domain1", domain1_result)
        self.assertIn("test_user2_domain1", domain1_result)
        self.assertIn("test_user3_domain1", domain1_result)
        domain2_result = self.e.get_users_for_role_in_domain("data2_admin", "domain2")
        self.assertIn("test_user1_domain2", domain2_result)
        self.assertNotIn("test_user2_domain1", domain2_result)
        self.assertNotIn("test_user3_domain1", domain2_result)

    def test_get_roles_for_user_in_domain(self):
        result = self.e.add_role_for_user_in_domain(
            "test_get_roles_for_user_in_domain", "data2_admin", "domain1"
        )
        self.assertTrue(result)
        result = self.e.add_role_for_user_in_domain(
            "test_get_roles_for_user_in_domain", "data3_admin", "domain1"
        )
        self.assertTrue(result)
        result = self.e.get_roles_for_user_in_domain(
            "test_get_roles_for_user_in_domain", "domain1"
        )
        self.assertIn("data2_admin", result)
        self.assertIn("data3_admin", result)

    def test_get_permissions_for_user_in_domain_case1(self):
        result = self.e.add_role_for_user_in_domain(
            "test_get_permissions_for_user_in_domain_case1", "data2_admin", "domain1"
        )
        self.assertTrue(result)
        self.e.add_role_for_user_in_domain(
            "test_get_permissions_for_user_in_domain_case1", "data3_admin", "domain1"
        )
        self.assertTrue(result)
        result = self.e.get_permissions_for_user_in_domain(
            "test_get_permissions_for_user_in_domain_case1", "domain1"
        )
        self.assertListEqual(result, [])

    def test_get_permissions_for_user_in_domain_case2(self):
        self.e.add_role_for_user_in_domain(
            "test_get_permissions_for_user_in_domain_case2", "data2_admin", "domain1"
        )
        self.e.add_role_for_user_in_domain(
            "test_get_permissions_for_user_in_domain_case2", "data3_admin", "domain1"
        )
        self.e.delete_roles_for_user_in_domain(
            "test_get_permissions_for_user_in_domain_case2", "data3_admin", "domain1"
        )
        result = self.e.get_roles_for_user_in_domain(
            "test_get_permissions_for_user_in_domain_case2", "domain1"
        )
        self.assertIn("data2_admin", result)

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
