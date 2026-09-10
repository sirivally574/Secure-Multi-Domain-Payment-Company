def evaluate_transaction(amount, balance, recipient):
    checks = []

    if amount <= 0:
        checks.append(("Amount validation", False))
    else:
        checks.append(("Amount validation", True))

    if amount > balance:
        checks.append(("Sufficient balance", False))
    else:
        checks.append(("Sufficient balance", True))

    if not recipient or len(recipient.strip()) < 3:
        checks.append(("Recipient validation", False))
    else:
        checks.append(("Recipient validation", True))

    failed_checks = sum(1 for _, passed in checks if not passed)

    if failed_checks > 0:
        risk_score = 80
        decision = "BLOCKED"
    else:
        risk_score = 10
        decision = "APPROVED"

    return {
        "checks": checks,
        "risk_score": risk_score,
        "decision": decision
    }