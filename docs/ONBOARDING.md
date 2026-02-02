# Onboarding Guide

## Goal
Enable a web application to safely call local services via the local agent, so that after pairing the agent accepts only requests authorized by the server signature.

Example use case: a cloud app that needs to print to a LAN device (e.g., a receipt printer).

## Steps
1) **Install the local agent** on the customer's machine (same LAN as the printer).
2) **First pairing (TOFU)**:
   - The app requests signed params from the signing server.
   - The browser sends them to the agent.
   - The agent pins the first valid public key for the given `kid`.
3) **Test print**:
   - Call `/api/sign` with a small payload.
   - Forward it to the agent and confirm success.
