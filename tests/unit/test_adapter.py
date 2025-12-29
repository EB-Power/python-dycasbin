import unittest
from unittest.mock import patch

from python_dycasbin import adapter

policy_line = "p, alice, data1, read"
table_name = "casbin_rule"


def mock_get_line_from_item(item):
    return policy_line


class TestAdapter(unittest.TestCase):
    def setUp(self):
        self.table_name = "casbin_rule"
        self.aws_endpoint_url = "http://localhost:8000"
        self.aws_region_name = "us-east-1"
        self.aws_access_key_id = "anything"
        self.aws_secret_access_key = "anything"
        self.aws_use_ssl = False
        self.aws_verify = False

    @patch("python_dycasbin.adapter.boto3.client")
    def test_create_table(self, mock_client):
        _ = adapter.Adapter(
            table_name=self.table_name,
            aws_endpoint_url=self.aws_endpoint_url,
            aws_region_name=self.aws_region_name,
            aws_access_key_id=self.aws_access_key_id,
            aws_secret_access_key=self.aws_secret_access_key,
            aws_use_ssl=self.aws_use_ssl,
            aws_verify=self.aws_verify,
        )

        mock_client.assert_called_once_with(
            "dynamodb",
            region_name="us-east-1",
            use_ssl=False,
            verify=False,
            endpoint_url="http://localhost:8000",
            aws_access_key_id="anything",
            aws_secret_access_key="anything",
            aws_session_token=None,
            aws_account_id=None,
        )

        mock_client.return_value.create_table.assert_called_once_with(
            TableName=self.table_name,
            AttributeDefinitions=[
                {"AttributeName": "id", "AttributeType": "S"},
                {"AttributeName": "v0", "AttributeType": "S"},
                {"AttributeName": "v1", "AttributeType": "S"},
            ],
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            ProvisionedThroughput={"ReadCapacityUnits": 10, "WriteCapacityUnits": 10},
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "v0-v1-index",
                    "KeySchema": [
                        {"AttributeName": "v0", "KeyType": "HASH"},
                        {"AttributeName": "v1", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
                {
                    "IndexName": "v1-v0-index",
                    "KeySchema": [
                        {"AttributeName": "v1", "KeyType": "HASH"},
                        {"AttributeName": "v0", "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                },
            ],
            BillingMode="PAY_PER_REQUEST",
        )

    @patch("python_dycasbin.adapter.boto3.client")
    def test_dont_create_table(self, mock_client):
        _ = adapter.Adapter(
            table_name=self.table_name,
            table_create_table=False,
            aws_endpoint_url=self.aws_endpoint_url,
            aws_region_name=self.aws_region_name,
            aws_access_key_id=self.aws_access_key_id,
            aws_secret_access_key=self.aws_secret_access_key,
            aws_use_ssl=self.aws_use_ssl,
            aws_verify=self.aws_verify,
        )
        mock_client.return_value.create_table.assert_not_called()
