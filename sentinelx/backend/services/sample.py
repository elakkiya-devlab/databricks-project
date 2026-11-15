from datetime import timedelta

from backend.models.asset import Asset, utcnow


def demo_assets(now=None):
    now = now or utcnow()

    def date(days):
        return (now + timedelta(days=days)).isoformat()

    assets = []
    teams = ["Data Platform", "Revenue Analytics", "ML Engineering", "Finance Operations"]
    for number in range(1, 13):
        orphan = number in {3, 8, 11}
        owner = None if orphan else teams[number % len(teams)]
        parent = f"db:sp:{number}"
        common = dict(owner=owner, application=f"pipeline-{number:02d}", active=number != 8,
                      privileged=number in {3, 11}, created_at=date(-5 if number % 3 == 0 else -65))
        assets.append(Asset(id=parent, name=f"sp-pipeline-{number:02d}", kind="service_principal",
                            source="databricks", provider_id=str(number), **common))
        remaining = [-3, 5, 12, 25, 85, 120][number % 6]
        rotated = date(-5 if number % 3 == 0 else -65) if number != 11 else None
        assets.append(Asset(id=f"db:sp-secret:{number}", name=f"pipeline-{number:02d}/oauth-secret",
                            kind="sp_secret", source="databricks", expires_at=date(remaining),
                            last_rotated_at=rotated, parent_id=parent, provider_id=f"secret-{number}",
                            binding=f"pipeline-{number:02d}", rotation_supported=True, **common))
        assets.append(Asset(id=f"aws:secret:{number}", name=f"sentinelx/pipeline-{number:02d}",
                            kind="aws_secret", source="aws", last_rotated_at=rotated,
                            binding=f"pipeline-{number:02d}", rotation_enabled=number % 4 != 0,
                            rotation_supported=True, **common))
        assets.append(Asset(id=f"db:secret:{number}", name=f"production/pipeline-{number:02d}",
                            kind="databricks_secret", source="databricks", last_rotated_at=rotated,
                            binding=f"pipeline-{number:02d}", rotation_enabled=True,
                            rotation_supported=True, **common))
    for number in range(1, 17):
        kind = ["pat", "oauth", "application_credential"][number % 3]
        assets.append(Asset(id=f"db:{kind}:{number}", name=f"{kind}-integration-{number:02d}", kind=kind,
                            source="databricks", owner=None if number % 5 == 0 else teams[number % 4],
                            created_at=date(-10 if number % 3 == 0 else -90), expires_at=date(-2 if number % 4 == 0 else 60),
                            last_rotated_at=date(-10 if number % 3 == 0 else -90),
                            last_used_at=date(-45 if number % 5 == 0 else -2), active=number % 5 != 0,
                            privileged=number % 7 == 0))
    return assets