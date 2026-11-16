"""Lets the remediation agent resolve a governance finding or asset ID to the real AWS secret it should inspect.

A finding on a Databricks credential resolves to the AWS secret bound to it, so that the plan can rotate both platforms.
"""


def _bound_aws_secret(workspace, asset_id):
    return next((item for item in workspace.assets() if item["credential_type"] == "aws_secret" and item["parent_id"] == asset_id), None)


def make_resolver(workspace):
    def resolve(identifier):
        try:
            if identifier.startswith("SX-"):
                finding = workspace.finding(identifier)
                guide = workspace.guidance(identifier)
                asset = workspace.asset(finding["asset_id"])
            else:
                asset = workspace.asset(identifier)
                matches = workspace.findings(query=identifier)
                if not matches:
                    if asset["credential_type"] != "aws_secret":
                        return dict(unsupported=f"{identifier} has no open governance finding.")
                    return dict(secret_name=asset["name"], explanation=f"{identifier} has no open governance finding.")
                finding = matches[0]
                guide = workspace.guidance(finding["finding_id"])
        except (KeyError, StopIteration):
            return None
        target, via = asset, ""
        if asset["credential_type"] != "aws_secret":
            target = _bound_aws_secret(workspace, asset["id"])
            if target is None:
                return dict(unsupported=f"{finding['finding_id']} concerns a {finding['type_label']} with no bound AWS secret; "
                                        "use the Action Center workflow for it.")
            via = f" It is rotated through its bound AWS secret `{target['name']}` together with the Databricks credential."
        why = f"**{finding['finding_id']} · {finding['title']}** ({finding['risk_level']}). {guide['summary']}"
        return dict(secret_name=target["name"], finding_id=finding["finding_id"],
                    explanation=why + f" Recommended: {finding['recommended_action']}.{via}")
    return resolve
