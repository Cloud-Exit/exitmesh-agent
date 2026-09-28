# Air-gap profile

The air-gap profile runs the agent with no connection to ExitMesh. Detection, findings, and local investigation work unchanged; rule bundles arrive out of band; records are exported to files that carry the same record identity and ownership metadata as the tunnel, so importing them into ExitMesh follows the same ownership rules as a live session.

## Kubernetes

```yaml
# airgap-values.yaml
airgap:
  enabled: true
  bundles:
    configMap: exitmesh-bundles
  exportDir: /data/export
  persistenceSize: 60Gi
  spoolCapacity: 50Gi
enrollment:
  existingSecret: exitmesh-enrollment
image:
  repository: registry.internal.example/exitmesh/exitmesh-agent
  digest: sha256:<digest>
```

```sh
helm install exitmesh-agent oci://registry.internal.example/charts/exitmesh-agent --version <version> \
  --namespace default -f airgap-values.yaml
```

- `endpoint` is not required. The enrollment token is still required: a cluster token (`emx1_c_<target_id>_<secret>`) carries the `target_id`, so the writer knows its identity without contacting ExitMesh.
- The spool is enlarged (`airgap.spoolCapacity`, default 50Gi on a 60Gi PVC) because nothing drains it until records are exported and committed. The spool relief order still applies when it fills.
- The NetworkPolicy drops the ExitMesh egress rule; DNS, the API server, node agents, and lookback sources remain.

### Delivering rule bundles

Bundles use the same format and the same signature and key manifest verification as online delivery ([bundle-format.md](bundle-format.md)); an out-of-band key manifest is checked against the configured root set (`trust.roots`) and the persisted manifest sequence exactly like one received over the tunnel. Two ways to deliver them:

- **GitOps-applied ConfigMap** (recommended). Put the bundle, its signature, and the key manifest into a ConfigMap in the coordinator namespace and set `airgap.bundles.configMap`. Each file listed in `airgap.bundles.files` (default `keymanifest.json`, `bundle.tar.gz`, `bundle.sig`) is mounted read-only with `subPath` at `/etc/exitmesh/bundles/<file>`, so the agent sees regular files: it rejects symbolic links, which a plain ConfigMap volume uses. Drop `keymanifest.json` from the list when you ship no new manifest. `subPath` mounts do not follow ConfigMap updates, so after updating the ConfigMap restart the coordinator with `kubectl -n exitmesh rollout restart statefulset/exitmesh-agent-coordinator`. Binary files go in `binaryData`:

  ```sh
  kubectl -n exitmesh create configmap exitmesh-bundles --from-file=./bundle/ \
    --dry-run=client -o yaml > exitmesh-bundles.yaml
  ```

  `./bundle/` holds the files exactly as named in [bundle-format.md](bundle-format.md); `kubectl` stores non-UTF-8 files in `binaryData`. A ConfigMap is limited to 1 MiB in total.

- **Image-bundled.** Build a derived image that adds the bundle files to a directory, and set `airgap.bundles.imagePath` to it:

  ```dockerfile
  FROM ghcr.io/cloud-exit/exitmesh-agent@sha256:<digest>
  COPY bundles/ /usr/share/exitmesh/bundles/
  ```

  with `--set airgap.bundles.imagePath=/usr/share/exitmesh/bundles`.

The coordinator distributes the active bundle to node agents over the node API, as online. An invalid bundle is rejected and the last known good bundle stays active.

### Export

The coordinator writes export files under `airgap.exportDir` on its PVC. Each file is `EMHPX1` followed by a CBOR sequence: a header with `target_id`, `writer_id`, `incarnation`, `epoch`, `last_committed`, `exported_at`, and `agent_version`, then the exact bytes of every record in chain order (History Protocol section 10). The container image has no shell or `tar`, so fetch the export with the agent CLI, which streams it to standard output:

```sh
kubectl -n exitmesh exec exitmesh-agent-coordinator-0 -- \
  exitmesh-agent export --config /etc/exitmesh/config/agent.yaml --out - > exitmesh-$(date +%Y%m%d).emhpx
```

Carry the file across the air gap and import it in ExitMesh. The import follows the same ownership table as a hello, so a file from a superseded writer or a closed epoch is audited and never applied.

### Local investigation

Investigations are initiated from the local CLI against the same live data and limits as online investigations; see `exitmesh-agent --help` for the investigation subcommands shipped with your version.

## Hosts

Set `airgap.enabled: true`, `airgap.bundleDir`, and `airgap.exportDir` (default `/var/lib/exitmesh/export`) in `/etc/exitmesh/agent.yaml`, and install packages from a mirror of the signed package repository. Export with:

```sh
sudo -u exitmesh exitmesh-agent export --config /etc/exitmesh/agent.yaml --out /var/lib/exitmesh/export/exitmesh-$(hostname).emhpx
```

## Mirroring

Mirror the image by digest, the chart, and, for hosts, the package repository; the image reference and digest are shown on the connector page and in every release's notes. Commands are in [upgrades.md](upgrades.md#air-gap-mirroring).
