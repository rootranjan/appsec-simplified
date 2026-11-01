# How to Run a Threat Modeling Session (Part 3)

**Series:** [1 Basics](01-basics.md) · [2 Frameworks](02-frameworks.md) · 3 Run a session (this page) · [4 Vending machine](04-vending-machine.md) · [5 Automation](05-automation.md)

## Before the session (15 min of prep)
- Pick a **small scope**: one feature or one system, not "the whole platform".
- Collect: architecture doc, API specs, existing diagrams, past incidents.
- Invite: a developer who built it, an architect, QA, product, and a security person. 4–6 people max.
- Book 60–90 minutes. A whiteboard (or a shared diagram) is enough.

## Agenda (maps to the 4 questions)

| Time | Step | Output |
|---|---|---|
| 10 min | **Scope and assets**: what are we protecting, what is out of scope, what do we assume? | Scope, assets, assumptions |
| 15 min | **Draw the DFD**: entities, processes, stores, flows, trust boundaries. Number the flows | Diagram |
| 25 min | **Find threats**: walk each element and flow with STRIDE. Park debates, write everything down | Raw threat list |
| 15 min | **Rate and decide**: L × I, then mitigate / eliminate / transfer / accept | Prioritised table |
| 10 min | **Wrap up**: owners, tickets, tests, open questions, next review date | Action list |

Facilitation tips:
- The diagram must match **reality**, not the design doc. Ask the developer "is that really how it works?"
- Ask "what if?" questions: *What if this input is wrong? What if this party is malicious? What if this fails?*
- Don't solve in the finding phase. Collect first, fix later.
- Include physical, human and process threats if they matter.
- Write assumptions down. Wrong assumptions are the source of many breaches.

## Templates

### Threat table
| ID | Element / flow | STRIDE | Threat | L | I | Risk | Response | Mitigation | Owner | Ticket | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|

### Scoring scale (write this on the page so everyone uses the same one)

| Score | Likelihood | Impact |
|---|---|---|
| 1 Low | Needs special skill, access or cost; unlikely | Minor loss, easily recovered |
| 2 Medium | Possible for a motivated attacker | Noticeable loss or short outage |
| 3 High | Easy, repeatable, or automated | Large loss, safety issue, fleet-wide, data breach |

Risk = L × I → **1–2 Low · 3–4 Medium · 6–9 High**.

### Security requirements (turn threats into testable statements)
Bad: "Make the payment secure."
Good: "The machine dispenses only after the backend confirms the payment status directly with the payment provider for the same order id and amount." → testable.

## Definition of done
- [ ] DFD reviewed by someone who knows the system
- [ ] Every threat has a response and an owner
- [ ] High risks have tickets with dates
- [ ] Each mitigation has a way to verify it (test, review, alert)
- [ ] Assumptions and open questions are written down
- [ ] Model stored in the repo, with a **next review trigger**

## Triggers to revisit the model
New feature or integration · new data type (especially personal data) · new user role · architecture change · a security incident · a new threat in your industry · at least once a year.

## Connecting to the rest of AppSec
| From the threat model | Do |
|---|---|
| Untrusted input reaches a parser or DB | Targeted code review, SAST rule, fuzzing |
| Auth or access control threats | Test with roles; see [Mass Assignment](../03-access-control/mass-assignment.md) and IDOR checks |
| Third-party flow | Review contract, signature verification, timeouts |
| Supply chain (firmware, packages) | SBOM, signing, pinned versions |
| High-risk flows | Feed to pen test scope |

Next: [Part 4: Worked example, office vending machine](04-vending-machine.md)
