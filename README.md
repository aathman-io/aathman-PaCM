# Aathman PaCM

**PaCM (Policy-as-Code for Models)** is a lightweight policy enforcement layer built on top of **Aathman Core**.  
It consumes verified facts about a machine-learning model and applies explicit organizational rules to decide whether the model is allowed to be used.

PaCM does not perform cryptography, fingerprinting, or verification itself.  
It relies entirely on Aathman Core for truth and focuses strictly on governance and decision-making.

---

## Why PaCM Exists

In real systems, detection alone is insufficient. Decisions must be enforced.

- **Aathman Core** answers:  
  “Is this model authentic and unchanged?”

- **PaCM** answers:  
  “Given that truth, is this model allowed?”

This separation mirrors real-world security and governance systems, where verification and authorization are distinct responsibilities.

---

## What PaCM Does

PaCM performs three clear steps:

1. **Verification (via Aathman Core)**  
   PaCM invokes Aathman Core to verify the model and its certificate.  
   Aathman returns structured facts such as:
   - signature validity  
   - fingerprint match  
   - signer public key  
   - parameter count  

2. **Policy Evaluation**  
   PaCM loads a policy file written as code and evaluates explicit rules against those verified facts.

3. **Deterministic Decision**  
   PaCM produces a clear decision:
   - `ALLOW`
   - `DENY`

Each decision includes a concise, human-readable reason.

---

## Policy Format (v0.1)

PaCM uses a minimal YAML-based policy.

```yaml
version: pacm-v1

requirements:
  signature_required: true

allowed_signers:
  - name: "aathman-root"
    public_key: "<HEX_ED25519_PUBLIC_KEY>"

constraints:
  max_parameter_count: 5000000

```
This policy enforces:

mandatory cryptographic signatures

an explicit trust list of allowed signers

a maximum model size constraint

Malformed or incomplete policies fail fast.

##Usage

Run PaCM from the repository root:

python pacm.py <model.pth> <model.pth.aathman.json> <policy.yaml>


Example when Aathman Core is checked out as a sibling repository:

python pacm.py ../aathman-core/model.pth ../aathman-core/model.pth.aathman.json policy.yaml

Output
Decision: ALLOW
Reason: Policy satisfied


Exit codes:

0 → ALLOW

1 → DENY

##Setup Note

For local usage, Aathman Core and Aathman PaCM are expected to be checked out as sibling directories:

parent-directory/

├── aathman-core/

└── aathman-pacm/


PaCM imports Aathman Core at runtime via this relative layout.
In packaged or production environments, Aathman Core would be installed as a standard Python dependency.

##Design Principles

Separation of concerns
Aathman verifies model identity. PaCM enforces policy.

Determinism
The same inputs always produce the same decision.

Minimalism
No databases, no networking, no heuristics.

Explainability
Every decision includes a clear reason.

##What PaCM Does Not Do

PaCM intentionally avoids:

behavioral or performance analysis

model diffing or drift detection

automatic remediation

learning or adaptive logic

It enforces policy. Nothing more.

##Relationship to Aathman Core

PaCM depends on Aathman Core as a verification engine.
Aathman Core remains policy-agnostic and focused solely on model integrity.

PaCM composes on top of Aathman without modifying its internals.

##Status

PaCM v0.1 is intentionally minimal and complete.
It is designed to demonstrate correct system composition, governance thinking, and enforceable trust boundaries.

##License

This project is licensed under the Apache License 2.0.
See LICENSE for details.

##Contributing

All contributions require signing the Contributor License Agreement (CLA).
Please review CLA.md before submitting changes.
