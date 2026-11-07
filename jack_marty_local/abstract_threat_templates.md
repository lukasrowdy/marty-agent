---
status: active
project: cybersecurity
type: reference
---
# Defensive Security Telemetry Reference Matrix

This file contains defensive detection guidance only. The maintained vault reference and its NAS mirror live in `07 - Resources/abstract_threat_templates.md`. The copy in the build package is a matching deployment reference.

## Windows and Linux process behavior

Windows event semantics: [Microsoft Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon). Event 10 records opening another process; it does not by itself prove memory was written or code injected. Correlation below is a detection hypothesis that needs validation.

### WIN-PROC-001 — Cross-process memory access followed by remote-thread creation
- **Platform:** Windows
- **Abstract behavior:** A process opens another process with memory-operation rights, writes or maps memory, then starts execution in that process.
- **Observable defensive telemetry:** Sysmon Event ID 10 (ProcessAccess), Event ID 8 (CreateRemoteThread), process creation ancestry, image hashes, signer, user, integrity level, target process, granted access mask, and time proximity between events.
- **Relevant event identifiers:** Sysmon 10 and 8; Windows Security 4688 where process creation auditing is enabled.
- **Detection considerations:** Correlate source and target process identifiers and time windows; consider legitimate debuggers, accessibility software, endpoint security, and instrumentation.
- **False-positive considerations:** Signed diagnostic tools, profilers, anti-cheat software, and security products can exhibit similar behavior.
- **Suggested defensive validation:** Confirm binary provenance and signer, parent process, expected deployment, and whether the target process is appropriate for the tool.

### WIN-PROC-002 — Unusual executable or script process ancestry
- **Platform:** Windows
- **Abstract behavior:** An office, browser, service, or scripting host launches an unexpected child process or interpreter chain.
- **Observable defensive telemetry:** Sysmon Event ID 1, Security 4688, command-line auditing, parent/child image paths, signer, user, integrity level, and execution policy events.
- **Relevant event identifiers:** Sysmon 1; Security 4688; PowerShell 4103/4104 when script-block logging is enabled.
- **Detection considerations:** Baseline software versions and common parent-child relationships; evaluate encoded or unusually long command lines as context rather than proof.
- **False-positive considerations:** Software installers, management agents, and developer tools often launch interpreters.
- **Suggested defensive validation:** Reproduce the expected workflow in a controlled test account and compare process ancestry and signed file hashes.

### LNX-PROC-001 — Unexpected interpreter or service child process
- **Platform:** Linux
- **Abstract behavior:** A daemon, web service, or desktop application spawns an uncommon shell, interpreter, or helper process.
- **Observable defensive telemetry:** auditd `execve` records, EDR process lineage, systemd journal, executable path, UID, parent PID, container identity, and cgroup.
- **Relevant event identifiers:** auditd syscall records for `execve`/`execveat`; systemd journal unit and process metadata.
- **Detection considerations:** Compare against host role and package-managed service definitions; account for container entrypoints.
- **False-positive considerations:** Maintenance jobs, package hooks, and health checks can create short-lived children.
- **Suggested defensive validation:** Check package ownership, service unit, deployment manifest, and a known-good host baseline.

## Suspicious use of native operating-system utilities

### CROSS-UTIL-001 — Rare administrative utility launched by an unexpected parent
- **Platform:** Windows and Linux
- **Abstract behavior:** A native administration or diagnostic utility runs outside its normal user, parent, host role, or maintenance window.
- **Observable defensive telemetry:** Process creation, command line, signer or package origin, parent-child lineage, account role, sudo/UAC events, and change ticket context.
- **Relevant event identifiers:** Sysmon 1; Security 4688/4672; Linux auditd `execve`, sudo logs, and journald.
- **Detection considerations:** Evaluate utility invocation with actor, arguments, destination, timing, and surrounding activity; utility presence alone is weak evidence.
- **False-positive considerations:** IT support, configuration management, incident response, and legitimate troubleshooting.
- **Suggested defensive validation:** Verify the operator, approved change, signed/package-managed binary, and expected target scope.

## Android and iOS application security

Reference: [Apple platform app security](https://support.apple.com/guide/security/app-security-overview-sec35dd877d0/web). Available management telemetry depends on OS, enrollment, and the management product; these entries are review templates, not promises that every device exposes each signal.

### MOBILE-APP-001 — App integrity or signing mismatch
- **Platform:** Android and iOS
- **Abstract behavior:** Installed application identity, signature, provisioning, or integrity state differs from the approved release.
- **Observable defensive telemetry:** MDM app inventory, package/bundle identifier, signer certificate, installation source, OS integrity attestation, and app version.
- **Relevant event identifiers:** Platform- and MDM-specific compliance events; use vendor event IDs from the deployed management product.
- **Detection considerations:** Compare against signed release manifests and managed distribution channels.
- **False-positive considerations:** Staged rollouts, enterprise signing renewal, and beta enrollment.
- **Suggested defensive validation:** Reconcile the app with the approved store or enterprise catalog and verify signing metadata.

### MOBILE-PERM-001 — Sensitive permission request inconsistent with app purpose
- **Platform:** Android and iOS
- **Abstract behavior:** An app requests or uses sensitive permissions that do not fit its documented function or user action.
- **Observable defensive telemetry:** MDM permission inventory, Android runtime permission/AppOps state, iOS privacy permission prompts and management logs, app version, foreground state, and user grant/revoke events.
- **Relevant event identifiers:** Android AppOps and package permission audit sources; iOS MDM/privacy telemetry as exposed by the configured platform.
- **Detection considerations:** Evaluate permission use over time and in relation to visible app features; APIs vary by OS version.
- **False-positive considerations:** Accessibility, navigation, communications, and assistive applications may need broad permissions.
- **Suggested defensive validation:** Reproduce the feature with least privilege and confirm the user-facing disclosure matches observed behavior.

## Suspicious overlays and application-permission abuse

### MOBILE-OVERLAY-001 — Overlay capability used around sensitive screens
- **Platform:** Android
- **Abstract behavior:** An application with overlay capability displays UI over another app, especially during authentication or payment flows.
- **Observable defensive telemetry:** AppOps overlay permission changes, package identity, foreground/background transitions, accessibility service state, and user reports or screen recording collected with consent.
- **Relevant event identifiers:** Android AppOps/package permission events; event names depend on OS and MDM telemetry.
- **Detection considerations:** Correlate overlay permission with app foreground state and sensitive workflow timing; do not infer maliciousness from capability alone.
- **False-positive considerations:** Chat heads, password managers, accessibility tools, and screen filters.
- **Suggested defensive validation:** Review the installed package source, declared purpose, permission history, and behavior in a managed test device.

### MOBILE-ACCESS-001 — Accessibility or device administration scope changes
- **Platform:** Android and iOS
- **Abstract behavior:** A new app obtains accessibility, device-management, or profile privileges that exceed its approved role.
- **Observable defensive telemetry:** MDM enrollment/profile changes, accessibility service enablement, device administrator state, app identity, and policy compliance events.
- **Relevant event identifiers:** MDM vendor audit events and platform management logs.
- **Detection considerations:** Treat privilege changes as review triggers and correlate with user consent and enrollment workflow.
- **False-positive considerations:** Assistive technology deployment and corporate enrollment.
- **Suggested defensive validation:** Confirm policy approval, user intent, and management profile provenance; revoke unapproved access through normal device administration.

## Unauthorized SMS access indicators

### MOBILE-SMS-001 — SMS permission or access inconsistent with application role
- **Platform:** Android
- **Abstract behavior:** An app requests SMS or call-log access without an approved messaging or telephony function.
- **Observable defensive telemetry:** Runtime permission grant history, package identity, default SMS role, Play Protect/MDM findings, and app permission audit records.
- **Relevant event identifiers:** Android permission/AppOps and MDM events; exact identifiers depend on platform version and vendor.
- **Detection considerations:** Check whether the app is the user-selected default handler and whether the feature requires the access.
- **False-positive considerations:** Approved messaging clients, carrier services, and accessibility scenarios.
- **Suggested defensive validation:** Revoke unnecessary permissions in a test device and verify the application’s documented core behavior.

### MOBILE-SMS-002 — Unexpected SMS-related app role or permission transition
- **Platform:** Android
- **Abstract behavior:** Default messaging role or SMS permission changes without a user-initiated, approved workflow.
- **Observable defensive telemetry:** Role manager changes, permission grant timestamps, installer source, foreground package, and MDM compliance history.
- **Relevant event identifiers:** Role/permission audit events where available; retain vendor-specific source names.
- **Detection considerations:** Correlate with user interaction and software updates; avoid content collection from message bodies.
- **False-positive considerations:** Device migration, app updates, or user-selected messaging client changes.
- **Suggested defensive validation:** Verify the change in device settings and management audit logs; do not collect SMS contents for validation.

## Cloud IAM misconfiguration

Reference: [AWS IAM security best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html). Adapt names and audit sources to the deployed cloud provider.

### CLOUD-IAM-001 — Excessive privilege or public trust relationship
- **Platform:** Cloud IAM
- **Abstract behavior:** A principal receives broad permissions or a trust policy permits unexpected identities or external principals.
- **Observable defensive telemetry:** Policy/configuration snapshots, cloud audit trail, principal identity, role assumption, permission boundary, resource scope, and change actor.
- **Relevant event identifiers:** Provider-specific IAM policy, role-assumption, and configuration-change events.
- **Detection considerations:** Compare effective permissions with role baselines and approved trust domains; account for inherited policies.
- **False-positive considerations:** Temporary incident roles, deployment automation, and managed service principals.
- **Suggested defensive validation:** Simulate effective access using provider-native analysis, verify owner and ticket, and narrow scope through change control.

### CLOUD-IAM-002 — Dormant or unusual credential activity
- **Platform:** Cloud IAM
- **Abstract behavior:** A dormant identity or credential is used from an unusual context or after a long inactive period.
- **Observable defensive telemetry:** Authentication audit events, credential age, source network metadata, MFA state, device/session context, and API action category.
- **Relevant event identifiers:** Provider-specific sign-in, token, access-key, and API audit events.
- **Detection considerations:** Use identity-specific baselines and correlate successful and denied activity without storing secret values.
- **False-positive considerations:** Disaster recovery, scheduled automation, and location changes from approved network egress.
- **Suggested defensive validation:** Confirm owner and workload, inspect secret rotation history, and use provider-native logs to validate the event.

## Network traffic anomalies

### NET-ANOM-001 — New or rare outbound destination pattern
- **Platform:** Network
- **Abstract behavior:** A host contacts a destination or service pattern not typical for its role or recent baseline.
- **Observable defensive telemetry:** Firewall, DNS resolver, proxy, flow records, destination reputation from approved sources, bytes, direction, protocol, and endpoint process lineage.
- **Relevant event identifiers:** Sensor-specific flow, firewall, DNS, and proxy events.
- **Detection considerations:** Compare by asset role and time window; use destination rarity as a triage signal rather than a verdict.
- **False-positive considerations:** Software updates, new SaaS features, CDN rotation, and backup traffic.
- **Suggested defensive validation:** Confirm the owning process and business service, then reproduce expected traffic from a controlled host.

### NET-ANOM-002 — Repeated connection failures or unusual beacon timing
- **Platform:** Network
- **Abstract behavior:** A host shows periodic connection attempts, repeated failures, or unusual volume to a small set of destinations.
- **Observable defensive telemetry:** NetFlow/IPFIX, firewall denies, DNS timing, proxy logs, endpoint process ancestry, and destination/port diversity.
- **Relevant event identifiers:** Sensor-specific connection and DNS events.
- **Detection considerations:** Account for polling agents, retry logic, NAT, and scheduled jobs; aggregate across enough time to avoid overfitting.
- **False-positive considerations:** Monitoring, telemetry agents, unreliable services, and captive networks.
- **Suggested defensive validation:** Compare against known service schedules and inspect the originating host process with authorized endpoint telemetry.
