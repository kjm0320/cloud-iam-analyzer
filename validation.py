def validate_policy(policy):
    if not isinstance(policy, dict):
        raise ValueError("정책의 최상위 구조는 JSON 객체여야 합니다.")

    statements = policy.get("Statement")

    if isinstance(statements, dict):
        statements = [statements]

    if not isinstance(statements, list) or not statements:
        raise ValueError(
            "Statement는 객체 또는 비어 있지 않은 객체 배열이어야 합니다."
        )

    for index, statement in enumerate(statements, start=1):
        if not isinstance(statement, dict):
            raise ValueError(
                f"Statement #{index}: JSON 객체여야 합니다."
            )

        if statement.get("Effect") not in ("Allow", "Deny"):
            raise ValueError(
                f"Statement #{index}: Effect는 Allow 또는 Deny여야 합니다."
            )