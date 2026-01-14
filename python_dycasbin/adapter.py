import hashlib
from typing import Any, Iterable

import boto3
from cachetools import TTLCache, cached
from casbin import Model, persist


class Adapter(persist.Adapter):
    """DynamoDB adopter for casbin

    Args:
        table_name: Dynamodb table name
        provision_policy_table: Provision a policy table if it doesnt exist
        table_definition: (Optional) Dynamodb table defintion. Please review the code to ensure you create a table with the proper structure.
          also see (https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dynamodb/client/create_table.html)
        table_provisioned_read_capacity: (Optional) Table read capacity units
        table_provisioned_write_capacity: (Optional) Table write capacity units
        table_billing_mode: (Optional) Table billing mode
        kwargs: Additional kwargs are passed to dynamodb client
    """

    def __init__(
        self,
        table_name: str = "casbin_rule",
        *,
        table_create_table: bool = True,
        table_definition: dict | None = None,
        table_read_capacity: int | None = 10,
        table_write_capacity: int | None = 10,
        table_billing_mode: str = "PROVISIONED",
        table_gsi_read_capacity: int | None = 10,
        table_gsi_write_capacity: int | None = 10,
        aws_endpoint_url: str | None = None,
        aws_region_name: str | None = None,
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
        aws_session_token: str | None = None,
        aws_use_ssl: bool | None = None,
        aws_verify: bool | None = None,
        aws_account_id: str | None = None,
    ) -> None:
        """create connection and dynamodb table"""
        self.WRITE_BATCH_SIZE = 25  # dynamodb batch size
        self.table_name = table_name
        self.aws_endpoint_url = aws_endpoint_url
        self.aws_region_name = aws_region_name
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.aws_session_token = aws_session_token
        self.aws_account_id = aws_account_id
        self.aws_use_ssl = aws_use_ssl
        self.aws_verify = aws_verify
        self.aws_account_id = aws_account_id

        if table_create_table:
            self._provision_table(
                table_name,
                table_definition,
                table_billing_mode,
                table_read_capacity,
                table_write_capacity,
                table_gsi_read_capacity,
                table_gsi_write_capacity,
            )

    @cached(cache=TTLCache(maxsize=1, ttl=300))
    def _get_db_handler(self):
        """Cache the dynamodb handler"""
        dynamodb = boto3.client(
            "dynamodb",
            region_name=self.aws_region_name,
            use_ssl=self.aws_use_ssl,
            verify=self.aws_verify,
            endpoint_url=self.aws_endpoint_url,
            aws_access_key_id=self.aws_access_key_id,
            aws_secret_access_key=self.aws_secret_access_key,
            aws_session_token=self.aws_session_token,
            aws_account_id=self.aws_account_id,
        )
        return dynamodb

    def _provision_table(
        self,
        table_name: str,
        table_definition: dict | None,
        table_billing_mode: str,
        table_provisioned_read_capacity: int | None,
        table_provisioned_write_capacity: int | None,
        gsi_read_capacity: int | None = -1,
        gsi_write_capacity: int | None = -1,
    ) -> None:
        """Provision the dynamodb table"""
        if table_definition is None:
            # Table definition
            # see (https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dynamodb/client/create_table.html)
            table_definition = {
                "TableName": table_name,
                "BillingMode": table_billing_mode,
                "KeySchema": [
                    {"AttributeName": "id", "KeyType": "HASH"},
                ],
                "AttributeDefinitions": [
                    {"AttributeName": "id", "AttributeType": "S"},
                    {"AttributeName": "v0", "AttributeType": "S"},
                    {"AttributeName": "v1", "AttributeType": "S"},
                ],
                "GlobalSecondaryIndexes": [
                    {
                        "IndexName": "v0-v1-index",
                        "KeySchema": [
                            {"AttributeName": "v0", "KeyType": "HASH"},
                            {"AttributeName": "v1", "KeyType": "RANGE"},
                        ],
                        "Projection": {
                            "ProjectionType": "ALL",
                        },
                    },
                    {
                        "IndexName": "v1-v0-index",
                        "KeySchema": [
                            {"AttributeName": "v1", "KeyType": "HASH"},
                            {"AttributeName": "v0", "KeyType": "RANGE"},
                        ],
                        "Projection": {
                            "ProjectionType": "ALL",
                        },
                    },
                ],
            }

        # Set table ProvisionedThroughput
        if (
            table_billing_mode == "PROVISIONED"
            or table_billing_mode == "ProvisionedThroughput"
        ):
            table_definition["ProvisionedThroughput"] = {
                "ReadCapacityUnits": table_provisioned_read_capacity,
                "WriteCapacityUnits": table_provisioned_write_capacity,
            }
            table_definition["GlobalSecondaryIndexes"][0]["ProvisionedThroughput"] = {
                "ReadCapacityUnits": gsi_read_capacity,
                "WriteCapacityUnits": gsi_write_capacity,
            }
            table_definition["GlobalSecondaryIndexes"][1]["ProvisionedThroughput"] = {
                "ReadCapacityUnits": gsi_read_capacity,
                "WriteCapacityUnits": gsi_write_capacity,
            }

        # Set gsi ProvisionedThroughput
        elif (
            table_billing_mode == "PAY_PER_REQUEST"
            or table_billing_mode == "OnDemandThroughput"
        ):
            table_definition["OnDemandThroughput"] = {
                "MaxReadRequestUnits": table_provisioned_read_capacity,
                "MaxWriteRequestUnits": table_provisioned_write_capacity,
            }
            table_definition["GlobalSecondaryIndexes"][0]["OnDemandThroughput"] = {
                "MaxReadRequestUnits": gsi_read_capacity,
                "MaxWriteRequestUnits": gsi_write_capacity,
            }
            table_definition["GlobalSecondaryIndexes"][1]["OnDemandThroughput"] = {
                "MaxReadRequestUnits": gsi_read_capacity,
                "MaxWriteRequestUnits": gsi_write_capacity,
            }

        dynamodb = self._get_db_handler()

        try:
            dynamodb.create_table(**table_definition)
        except dynamodb.exceptions.ResourceInUseException:
            pass

    def _write_batch(self, batch: list) -> None:
        """Batch multiple writes to improve performance."""
        dynamodb = self._get_db_handler()
        request_items = {self.table_name: batch}

        while request_items:
            response = dynamodb.batch_write_item(RequestItems=request_items)
            request_items = response.get("UnprocessedItems", {})

    def update_policy(
        self, sec: str, ptype: str, old_rule: Iterable, new_rule: Iterable
    ) -> bool:
        self.add_policy(sec, ptype, new_rule)
        self.remove_policy(sec, ptype, old_rule)
        return True

    def get_filtered_item(self, ptype: str, rules: Iterable) -> dict:
        dynamodb = self._get_db_handler()
        exp_attr = {":ptype": {"S": ptype}}
        filter_exp_list = []
        filter_exp_list.append("ptype = :ptype")

        for i, rule in enumerate(rules):
            exp_attr[":v{}".format(i)] = {"S": rule}
            filter_exp_list.append("v{} = :v{}".format(i, i))

        filter_exp = " and ".join(filter_exp_list)

        response = dynamodb.scan(
            ExpressionAttributeValues=exp_attr,
            FilterExpression=filter_exp,
            TableName=self.table_name,
        )

        data = response.get("Items", {})

        while "LastEvaluatedKey" in response:
            response = dynamodb.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
            data.extend(response["Items"])

        return data

    def load_policy_lines(self, response: dict, model: Model) -> None:
        for i in response["Items"]:
            persist.load_policy_line(self.get_line_from_item(i), model)

    def load_policy(self, model: Model):
        """load all policies from database"""
        dynamodb = self._get_db_handler()
        response = dynamodb.scan(TableName=self.table_name)
        self.load_policy_lines(response, model)

    def load_filtered_policy_by_sub(self, model: Model, sub: str) -> None:
        dynamodb = self._get_db_handler()
        response = dynamodb.query(
            TableName=self.table_name,
            IndexName="v0-v1-index",
            Select="ALL_ATTRIBUTES",
            KeyConditionExpression="v0 = :v0",
            ExpressionAttributeValues={":v0": {"S": sub}},
        )
        self.load_policy_lines(response, model)

    def load_filtered_policy_by_obj(self, model: Model, obj: str) -> None:
        dynamodb = self._get_db_handler()
        response = dynamodb.query(
            TableName=self.table_name,
            IndexName="v1-v0-index",
            Select="ALL_ATTRIBUTES",
            KeyConditionExpression="v1 = :v1",
            ExpressionAttributeValues={":v1": {"S": obj}},
        )
        self.load_policy_lines(response, model)

    def get_line_from_item(self, item: dict[str, Any]) -> str:
        """make casbin policy string from dynamodb item"""
        line = item["ptype"]["S"]
        i = 0

        while i < len(item) - 2:
            line = "{}, {}".format(line, item["v{}".format(i)]["S"])
            i = i + 1

        return line

    def get_md5(self, line: Iterable):
        """convert policy line to MD5 hash to be used as "id" """
        m = hashlib.md5()
        m.update(str(line).encode("utf-8"))
        return m.hexdigest()

    def convert_to_item(self, ptype: str, rule: Iterable):
        """change casbin policy string to dynamodb item"""
        line = {"ptype": {"S": ptype}}

        for i, v in enumerate(rule):
            line["v{}".format(i)] = {}
            line["v{}".format(i)]["S"] = v

        line["id"] = {"S": self.get_md5(line)}

        return line

    def save_policy(self, model: Model) -> bool:
        """Save all policy rules to DynamoDB."""
        write_requests = []

        for sec in ["p", "g"]:
            if sec not in model.model:
                continue

            for ptype, ast in model.model[sec].items():
                for rule in ast.policy:
                    item = self.convert_to_item(ptype, rule)
                    write_requests.append({"PutRequest": {"Item": item}})

                    if len(write_requests) == self.WRITE_BATCH_SIZE:
                        self._write_batch(write_requests)
                        write_requests = []

        if write_requests:
            self._write_batch(write_requests)

        return True

    def add_policy(self, _: str, ptype: str, rule: Iterable) -> None:
        """adds a single policy rule to the storage."""
        dynamodb = self._get_db_handler()
        line = self.convert_to_item(ptype, rule)
        dynamodb.put_item(TableName=self.table_name, Item=line)

    def remove_policy(self, _: str, ptype: str, rule: Iterable) -> bool:
        """removes a single policy rule from the storage."""
        dynamodb = self._get_db_handler()
        line = self.convert_to_item(ptype, rule)

        dynamodb.delete_item(
            Key={"id": {"S": line["id"]["S"]}},
            TableName=self.table_name,
        )

        return True

    def remove_filtered_policy(
        self, _: str, ptype: str, field_index: int, *field_values: Iterable
    ) -> bool:
        """Removes policy rules that match the filter from the storage."""

        if not (0 <= field_index <= 5):
            return False
        if not (1 <= field_index + len(field_values) <= 6):
            return False

        matched_rules = self.get_filtered_item(ptype, list(field_values))
        if not matched_rules:
            return True

        batch = []

        for rule in matched_rules:
            batch.append({"DeleteRequest": {"Key": {"id": rule["id"]}}})

            if len(batch) == self.WRITE_BATCH_SIZE:
                self._write_batch(batch)
                batch = []

        if batch:
            self._write_batch(batch)

        return True
