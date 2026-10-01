# Security policy

The ExitMesh Telemetry Agent runs with read access to Kubernetes clusters and Linux hosts. We treat every report that could weaken its read-only, outbound-only boundary as a priority.

## Supported versions

Security fixes are released for the latest minor release and the previous minor release. The control plane's compatibility matrix lists which agent versions are still supported; an agent below the minimum is flagged as outdated on its connector page.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability** (GitHub private vulnerability reporting). Do not open a public issue, pull request, or discussion for a suspected vulnerability.

Include the affected version, the install form (Helm chart or host package), the configuration involved, reproduction steps, and the impact you observed. Reports about the ExitMesh control plane are accepted through the same channel and routed internally.

## What happens next

1. We acknowledge the report within 3 business days.
2. We confirm or reject the issue and share an initial severity assessment within 10 business days.
3. We develop the fix in a private fork, request a CVE where appropriate, and agree a disclosure date with you. The default embargo is 90 days from the report, shortened when a fix ships earlier or when the issue is exploited in the wild.
4. We publish the fixed release, a GitHub security advisory, and release notes naming the affected versions, the fixed version, and the upgrade command. Reporters are credited unless they ask not to be.

## Scope

In scope: the agent binary, the Helm chart, the deb, rpm, and tarball packages, the systemd unit, the History Protocol implementation in `pkg/protocol`, the rule bundle verifier, and the release pipeline (signatures, SBOMs, provenance).

Examples of issues we want to hear about: any path by which the agent writes to the Kubernetes API, executes a command, reads a Secret, opens an inbound listener other than the node-to-coordinator Service, or writes outside `/var/lib/exitmesh` or the coordinator volume; a node agent submitting records for another node; redaction bypasses that let secrets reach the evidence ring, spool, transmission, or logs; scope-injection bypasses in investigation queries; acceptance of an unsigned, revoked, or rolled-back rule bundle or key manifest; and weaknesses in the tunnel, enrollment, or credential handling.

## Rule bundle signing keys and root key compromise

Rule bundles are signed with rotating signing keys published in a key manifest that is itself signed by the agent trust root of the ExitMesh workspace. Every workspace has its own trust root, generated in ExitMesh under Settings > General > Encryption > Agent trust root; its private key stays in the ExitMesh Vault and agents receive only the public half, configured on each agent (`trust.roots`) from the connector page and never built into agent releases. Signing-key compromise is handled without touching agents: the deployment publishes a key manifest with a higher sequence number that revokes the key, and agents reject bundles signed by it from then on, over the tunnel and out of band alike.

Compromise of a root key cannot be repaired by a manifest, because the compromised root could sign a manifest of its own. If a workspace's trust root is compromised, a workspace administrator:

1. replaces the workspace's agent trust root in ExitMesh, so current bundles and key manifests are signed under the new root;
2. replaces `trust.roots` on every agent of the workspace with the new public key (Helm upgrade, GitOps change, or configuration management for hosts) and clears the persisted trust state with the new configuration, so agents reject anything signed only by the compromised root;
3. reviews findings delivered since the suspected compromise.

A vulnerability in the agent's verification code itself is handled as an agent security release under this policy.

## Package repository and release signing

Container images, the Helm chart, release archives, checksums, and SBOMs are signed with cosign keyless signing from this repository's release workflow. deb and rpm packages and the package repositories are signed with a dedicated package key that is never used for rule bundles. Verification commands are in each release's notes and in `docs/security.md`.
