import time
import unittest

import boto3
from botocore.exceptions import NoCredentialsError
from botocore.stub import Stubber

from backend.services.aws_connection import NOT_CONFIGURED_MESSAGE, AwsConfig, AwsConnector

ROLE = "arn:aws:iam::111122223333:role/sentinelx-discovery"
CALLER = {"UserId": "AROAEXAMPLE:session", "Account": "111122223333", "Arn": "arn:aws:sts::111122223333:assumed-role/sentinelx-discovery/s"}
ASSUMED = {"Credentials": {"AccessKeyId": "ASIATESTTESTTESTTEST", "SecretAccessKey": "testing", "SessionToken": "token",
                           "Expiration": "2030-01-01T00:00:00Z"}}


def config(**overrides):
    values = dict(account_id="111122223333", region="us-east-1", role_arn=ROLE, auth_method="assume_role")
    values.update(overrides)
    return AwsConfig(**values)


def factory(plan):
    """plan: {service: [(operation, response_or_error_code)]}; one stubbed client per service, calls must follow the plan order."""
    clients = {}

    def build(service, **kwargs):
        if service not in clients:
            client = boto3.client(service, region_name="us-east-1", aws_access_key_id="testing", aws_secret_access_key="testing")
            stubber = Stubber(client)
            for operation, outcome in plan[service]:
                if isinstance(outcome, str):
                    stubber.add_client_error(operation, service_error_code=outcome)
                else:
                    stubber.add_response(operation, outcome)
            stubber.activate()
            clients[service] = client
        return clients[service]

    return build


class AwsConnectionTests(unittest.TestCase):
    def test_not_configured_never_calls_aws_or_claims_success(self):
        def explode(*args, **kwargs):
            raise AssertionError("AWS must not be called")

        result = AwsConnector(AwsConfig.from_env({}), explode).test_connection()
        self.assertEqual(result.status, "not_configured")
        self.assertEqual(result.message, NOT_CONFIGURED_MESSAGE)
        self.assertFalse(result.connected)

    def test_config_from_environment(self):
        loaded = AwsConfig.from_env({"SENTINELX_AWS_ACCOUNT_ID": "111122223333", "SENTINELX_AWS_REGION": "us-east-1",
                                     "SENTINELX_AWS_ROLE_ARN": ROLE})
        self.assertTrue(loaded.configured)
        self.assertEqual(loaded.auth_method, "assume_role")
        sso = AwsConfig.from_env({"SENTINELX_AWS_SSO_START_URL": "https://example.awsapps.com/start"})
        self.assertEqual(sso.auth_method, "identity_center")
        self.assertIn("account_id", sso.missing())

    def test_connected_only_after_identity_and_permission_checks(self):
        plan = {"sts": [("assume_role", ASSUMED), ("get_caller_identity", CALLER)],
                "secretsmanager": [("list_secrets", {"SecretList": []})]}
        result = AwsConnector(config(), factory(plan)).test_connection()
        self.assertTrue(result.connected, result.message)
        self.assertEqual(result.identity_arn, CALLER["Arn"])
        self.assertTrue(result.permissions["secretsmanager:ListSecrets"])
        self.assertNotIn("testing", repr(result))
        self.assertNotIn("token", repr(result))

    def test_assume_role_denied_is_failure(self):
        result = AwsConnector(config(), factory({"sts": [("assume_role", "AccessDenied")]})).test_connection()
        self.assertEqual(result.status, "failed")
        self.assertIn("AccessDenied", result.message)

    def test_missing_identity_is_failure(self):
        def no_credentials(service, **kwargs):
            raise NoCredentialsError()

        result = AwsConnector(config(), no_credentials).test_connection()
        self.assertEqual(result.status, "failed")
        self.assertFalse(result.connected)

    def test_account_mismatch_is_failure(self):
        plan = {"sts": [("assume_role", ASSUMED), ("get_caller_identity", {**CALLER, "Account": "999999999999"})]}
        result = AwsConnector(config(), factory(plan)).test_connection()
        self.assertEqual(result.status, "failed")
        self.assertIn("does not match", result.message)

    def test_missing_secretsmanager_permission_is_failure(self):
        plan = {"sts": [("assume_role", ASSUMED), ("get_caller_identity", CALLER)],
                "secretsmanager": [("list_secrets", "AccessDeniedException")]}
        result = AwsConnector(config(), factory(plan)).test_connection()
        self.assertEqual(result.status, "failed")
        self.assertFalse(result.permissions["secretsmanager:ListSecrets"])

    def test_identity_center_requires_login_then_validates_credentials(self):
        sso = config(auth_method="identity_center", role_arn="", sso_start_url="https://example.awsapps.com/start",
                     sso_region="us-east-1", sso_role_name="SentinelXDiscovery")
        self.assertEqual(AwsConnector(sso, lambda *a, **k: None).test_connection().status, "login_required")
        expired = {"access_key_id": "a", "secret_access_key": "b", "session_token": "c", "expiration": 1}
        self.assertEqual(AwsConnector(sso, lambda *a, **k: None).test_connection(expired).status, "login_required")
        fresh = {"access_key_id": "ASIATEST", "secret_access_key": "x", "session_token": "t",
                 "expiration": (time.time() + 3600) * 1000}
        plan = {"sts": [("get_caller_identity", CALLER)], "secretsmanager": [("list_secrets", {"SecretList": []})]}
        self.assertTrue(AwsConnector(sso, factory(plan)).test_connection(fresh).connected)

    def test_device_authorization_flow(self):
        sso = config(auth_method="identity_center", role_arn="", sso_start_url="https://example.awsapps.com/start",
                     sso_region="us-east-1", sso_role_name="SentinelXDiscovery")
        start = {"clientId": "cid", "clientSecret": "csecret", "clientIdIssuedAt": 1, "clientSecretExpiresAt": 2}
        auth = {"deviceCode": "dc", "userCode": "ABCD-EFGH", "verificationUri": "https://device.sso.us-east-1.amazonaws.com/",
                "verificationUriComplete": "https://device.sso.us-east-1.amazonaws.com/?user_code=ABCD-EFGH",
                "expiresIn": 600, "interval": 1}
        plan = {"sso-oidc": [("register_client", start), ("start_device_authorization", auth),
                             ("create_token", "AuthorizationPendingException"), ("create_token", {"accessToken": "at"})],
                "sso": [("get_role_credentials", {"roleCredentials": {
                    "accessKeyId": "ASIATEST", "secretAccessKey": "x", "sessionToken": "t", "expiration": 4102444800000}})]}
        connector = AwsConnector(sso, factory(plan))
        flow = connector.start_login()
        self.assertEqual(flow["user_code"], "ABCD-EFGH")
        self.assertEqual(connector.poll_login(flow), ("pending", None))
        state, credentials = connector.poll_login(flow)
        self.assertEqual(state, "authorized")
        self.assertEqual(credentials["access_key_id"], "ASIATEST")
        self.assertEqual(connector.poll_login({**flow, "expires_at": 0}), ("expired", None))


if __name__ == "__main__":
    unittest.main()
