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

        for field in ("NotAction", "NotResource"):
            if field in statement:
                raise ValueError(
                    f"Statement #{index}: "
                    f"현재 분석기는 {field} 분석을 지원하지 않습니다."
                )

        for field in ("Action", "Resource"):
            if field not in statement:
                raise ValueError(
                    f"Statement #{index}: {field}가 누락되었습니다."
                )

            value = statement[field]

            if isinstance(value, str):
                values = [value]
            elif isinstance(value, list):
                values = value
            else:
                raise ValueError(
                    f"Statement #{index}: "
                    f"{field}는 문자열 또는 문자열 배열이어야 합니다."
                )

            if not values:
                raise ValueError(
                    f"Statement #{index}: {field} 배열이 비어 있습니다."
                )

            for item in values:
                if not isinstance(item, str) or not item.strip():
                    raise ValueError(
                        f"Statement #{index}: "
                        f"{field}에는 비어 있지 않은 문자열만 허용됩니다."
                    )