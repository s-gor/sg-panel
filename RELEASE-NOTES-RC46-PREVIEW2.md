# SG-Panel v0.10.0 RC46 Multi-Node — Preview 2

Preview 2 adds the first real, deliberately limited deployment path from the central SG-Panel to a remote SG-Node.

## Added

- A central job queue bound to an individual registered node.
- Agent polling for pending jobs over the existing authenticated HTTPS connection.
- A separate privileged SG-Node Worker; the network-facing agent remains an unprivileged `sg-node` service.
- Safe application of an Xray configuration on a node:
  - temporary file;
  - SHA-256 verification;
  - `xray run -test`;
  - backup of the previous `config.json`;
  - atomic replacement;
  - service restart and health check;
  - automatic rollback on failure.
- First pilot deployment from the node card: one `VLESS REALITY` connection on a separate TCP port.
- Generated client link after a successful deployment.
- Job status and result history on the node card.
- Automatic detection of the active node profile and the number of clients from the applied Xray configuration.
- Copy-button fallback for HTTP access where `navigator.clipboard` is unavailable.
- Green spinner, elapsed time and clean logging in the SG-Node installer.

## Fixed

- The SG-Node Agent source file was inaccessible to the `sg-node` service because `/opt/sg-node` had the wrong group permissions.
- Installer errors now show useful log lines instead of only `Agent stopped before registration`.

## Deliberate limitations

- Preview 2 deploys only one VLESS REALITY inbound.
- It uses a separate public TCP port such as 8443 and does not change Nginx on 80/443.
- The selected port must be opened manually in the cloud firewall after a successful deployment.
- XHTTP-TLS, Hysteria 2, multiple inbounds, shared subscriptions and bulk client deployment are not enabled yet.
