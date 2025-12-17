"""
PaCM — Policy-as-Code for Models

PaCM is a policy enforcement layer that consumes verified facts
from Aathman and makes allow/deny decisions based on a policy file.
"""

import sys
import os
import yaml
from typing import Dict


class PaCMDecision:
    ALLOW = "ALLOW"
    DENY = "DENY"
    WARN = "WARN"


def load_policy(policy_path: str) -> Dict:
    """
    Load and validate the policy.yaml file.
    """
    with open(policy_path, "r", encoding="utf-8") as f:
        policy = yaml.safe_load(f)

    if not isinstance(policy, dict):
        raise ValueError("Policy file must be a YAML mapping")

    if policy.get("version") != "pacm-v1":
        raise ValueError("Unsupported or missing policy version")

    if "requirements" not in policy:
        raise ValueError("Policy missing 'requirements' section")

    if "allowed_signers" not in policy:
        raise ValueError("Policy missing 'allowed_signers' section")

    if "constraints" not in policy:
        raise ValueError("Policy missing 'constraints' section")

    if not isinstance(policy["allowed_signers"], list):
        raise ValueError("'allowed_signers' must be a list")

    if "signature_required" not in policy["requirements"]:
        raise ValueError("Policy missing 'signature_required' requirement")

    if "max_parameter_count" not in policy["constraints"]:
        raise ValueError("Policy missing 'max_parameter_count' constraint")

    return policy


def evaluate_policy(policy: Dict, facts: Dict) -> Dict:
    # 1) Signature requirement
    if policy["requirements"].get("signature_required", False):
        if not facts.get("signature_valid", False):
            return {
                "decision": PaCMDecision.DENY,
                "reason": "Signature required but invalid or missing"
            }

    # 2) Allowed signers
    allowed_keys = {
        s.get("public_key")
        for s in policy.get("allowed_signers", [])
    }
    signer_key = facts.get("signer_public_key")

    if signer_key not in allowed_keys:
        return {
            "decision": PaCMDecision.DENY,
            "reason": "Signer is not in allowed_signers"
        }

    # 3) Parameter count constraint
    max_params = policy["constraints"].get("max_parameter_count")
    param_count = facts.get("parameter_count")

    if max_params is not None and param_count is not None:
        if param_count > max_params:
            return {
                "decision": PaCMDecision.DENY,
                "reason": "Model exceeds max_parameter_count"
            }

    # 4) Fingerprint mismatch (defensive)
    if not facts.get("fingerprint_match", False):
        return {
            "decision": PaCMDecision.DENY,
            "reason": "Fingerprint mismatch"
        }

    return {
        "decision": PaCMDecision.ALLOW,
        "reason": "Policy satisfied"
    }



def main():
    if len(sys.argv) != 4:
        print("Usage: pacm.py <model.pth> <cert.json> <policy.yaml>")
        sys.exit(2)

    model_path = sys.argv[1]
    cert_path = sys.argv[2]
    policy_path = sys.argv[3]

    # Load policy
    try:
        policy = load_policy(policy_path)
    except Exception as e:
        print("Policy error:", str(e))
        sys.exit(1)

    # Import Aathman verifier (local dependency)
    AATHMAN_PATH = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../aathman-core")
    )
    sys.path.append(AATHMAN_PATH)

    try:
        from verify import verify_model
    except Exception as e:
        print("Failed to import Aathman verifier:", str(e))
        sys.exit(1)

    # Run Aathman verification
    try:
        facts = verify_model(model_path, cert_path)
    except Exception as e:
        print("Aathman verification failed:", str(e))
        sys.exit(1)

    # Evaluate policy
    result = evaluate_policy(policy, facts)

    print(f"Decision: {result['decision']}")
    print(f"Reason: {result['reason']}")

    if result["decision"] == PaCMDecision.DENY:
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
