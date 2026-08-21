# Identity / Anchor

This module is the identity control plane. It will resolve and publish DID / webvh state, public device projections, endpoints, and push registrations.

It may persist public identity metadata. It must not read, index, or restore vault payloads, and it must not depend on mediation storage.
