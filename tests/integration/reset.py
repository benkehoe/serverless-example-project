# Copyright 2023 Ben Kehoe
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# https://www.apache.org/licenses/LICENSE-2.0
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.

import boto3


def reset(session: boto3.Session, stack_name: str):
    cloudformation = session.resource("cloudformation")
    stack = cloudformation.Stack(stack_name)
    cfn_table = stack_resource = stack.Resource("Table")
    table_name = cfn_table.physical_resource_id
    dynamodb = session.client("dynamodb")
    paginator = dynamodb.get_paginator("scan")
    for response in paginator.paginate(TableName=table_name):
        for item in response.get("Items", []):
            pk = item["pk"]
            sk = item["sk"]
            print(f"Deleting item {pk} {sk}")
            dynamodb.delete_item(TableName=table_name, Key={"pk": pk, "sk": sk})


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--stack-name", required=True)
    parser.add_argument("--profile")
    args = parser.parse_args()
    session = boto3.Session(profile_name=args.profile)
    reset(session, args.stack_name)
