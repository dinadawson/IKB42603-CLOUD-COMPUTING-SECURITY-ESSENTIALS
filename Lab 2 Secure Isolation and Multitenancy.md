# Lab 2: Secure Isolation and Multi-Tenancy

**Course:** IKB42603 Cloud Computing Security Essentials

**Name:** NUR IRDINA SYAQELA BINTI MOHD SHUKRI

**Lecturer:** MADAM ADNI

**Date:** 10 August 2026


## Objectives

This lab demonstrates tenant isolation across three security dimensions:

1. **Compute isolation** using containers, Kubernetes namespaces, and a resource quota.
2. **Network isolation** using a Calico-enforced default-deny `NetworkPolicy`.
3. **Storage and secret isolation** using namespace-scoped RBAC.
4. **Secure deletion awareness** through normal deletion, overwriting, and the cloud concept of cryptographic erasure.

## Setup — Kubernetes Cluster with Calico

### Step 1: Create the kind cluster

The cluster was created with the default CNI disabled and the pod network set to `192.168.0.0/16`:

```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: 192.168.0.0/16
```

### Step 2: Install and verify Calico

Calico v3.27.0 was applied:

```bash
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calico.yaml
kubectl -n kube-system rollout status daemonset/calico-node --timeout=180s
```

**Result:** `daemon set "calico-node" successfully rolled out` — the cluster was ready with a CNI capable of enforcing NetworkPolicies.

## Task 1 — Two Tenants on One Cluster

### Procedure

```bash
kubectl create namespace tenant-a
kubectl create namespace tenant-b
kubectl -n tenant-a create deployment web --image=nginx
kubectl -n tenant-b create deployment web --image=nginx
kubectl -n tenant-a expose deployment web --port=80
kubectl -n tenant-b expose deployment web --port=80
kubectl get pods,svc -n tenant-a
```

<img width="625" height="414" alt="Task 1" src="https://github.com/user-attachments/assets/91a78eba-04b9-41e9-a19c-ee05470acb30" />


**Observed result:** `pod/web-7887448d46-snxmm` reached `1/1 Running`, and `service/web` was assigned ClusterIP `10.96.248.147` on port 80/TCP.

**Security interpretation:** Namespaces separate names and administrative scope, but they do not by themselves create a network security boundary between tenants sharing the same cluster.

## Task 2 — Observe the Default-Open Risk

### Procedure

```bash
kubectl get svc web -n tenant-b -o jsonpath='{.spec.clusterIP}'; echo
kubectl -n tenant-a run probe --rm -it --image=curlimages/curl --restart=Never \
  -- curl -s -m 5 http://10.96.27.22 -o /dev/null -w 'HTTP %{http_code}\n'
```

<img width="645" height="279" alt="Task 2" src="https://github.com/user-attachments/assets/3275fee2-52ba-4cc0-abdf-ad4b7366d413" />


**Observed result:** `HTTP 200` — the probe from `tenant-a` successfully reached `tenant-b`'s service at `10.96.27.22`.

**Security interpretation:** Tenant A could reach Tenant B because Kubernetes pod-to-pod networking is open by default unless a NetworkPolicy explicitly restricts it. This confirms the multi-tenancy risk: namespace separation alone did not prevent cross-tenant traffic.

## Task 3 — Contain the Noisy Neighbour (Resource Quota)

### Procedure

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: tenant-a-quota
  namespace: tenant-a
spec:
  hard:
    requests.cpu: "1"
    requests.memory: 512Mi
    pods: "5"
```

```bash
kubectl describe resourcequota tenant-a-quota -n tenant-a
```

<img width="741" height="679" alt="Task 3 and 4 Policy" src="https://github.com/user-attachments/assets/49f72772-7143-4175-9ce3-67c10445b13c" />


**Observed result:** The quota capped Tenant A at 5 pods, 1 requested CPU, and 512Mi requested memory. At the time of inspection, 1 pod was counted, with CPU/memory requests at 0 since the `nginx` deployment did not declare explicit resource requests.

**Security interpretation:** The quota limits how much shared compute capacity Tenant A can reserve, reducing noisy-neighbour and resource-exhaustion risk on shared infrastructure. In production, workloads should also declare container-level `requests`/`limits` so CPU and memory accounting is meaningful.

**Note on quota enforcement:** Applying this quota also caused the Kubernetes API server to reject a later ad-hoc pod (`probe`) with `Error from server (Forbidden): ... must specify requests.cpu for: probe; requests.memory for: probe`, since any new pod in `tenant-a` must now declare resource requests. This is expected quota behaviour and was worked around in Task 4 by briefly removing and reapplying the quota around the verification probe.

## Task 4 — Default-Deny Network Isolation

### Procedure

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: tenant-b
spec:
  podSelector: {}
  policyTypes: [Ingress]
```

The same probe from Task 2 was re-run against the same IP (`10.96.27.22`) after the policy was applied:

```bash
kubectl -n tenant-a run probe --rm -it --image=curlimages/curl --restart=Never \
  -- curl -s -m 5 http://10.96.27.22 -o /dev/null -w 'HTTP %{http_code}\n'
```

<img width="741" height="679" alt="Task 4 Probe Result" src="https://github.com/user-attachments/assets/bf4ca97e-ab70-49f4-a292-100bf391b986" />


**Observed result:** `HTTP 000` — no HTTP response was received, versus `HTTP 200` in Task 2 before the policy existed.

**Security interpretation:** The `default-deny-ingress` policy selects every pod in `tenant-b` (`podSelector: {}`) and declares `Ingress` as the controlled direction with no allow rules, so Calico blocks all incoming connections to `tenant-b`. This before/after pair (`HTTP 200` → `HTTP 000`) is direct evidence of enforced network segmentation. Note that this policy also blocks legitimate same-namespace traffic within `tenant-b`, since no allow rule was added — in production, a same-namespace allow rule would be layered on top.

## Task 5 — Storage and Secret Isolation

### Procedure

```bash
kubectl -n tenant-a create secret generic data --from-literal=value=SECRET_A
kubectl -n tenant-b create secret generic data --from-literal=value=SECRET_B

kubectl -n tenant-a create serviceaccount app-a
kubectl -n tenant-a create role reader --verb=get --resource=secrets
kubectl -n tenant-a create rolebinding rb --role=reader --serviceaccount=tenant-a:app-a

SA=system:serviceaccount:tenant-a:app-a
kubectl auth can-i get secrets -n tenant-a --as=$SA
kubectl auth can-i get secrets -n tenant-b --as=$SA
```

<img width="741" height="679" alt="Task 5" src="https://github.com/user-attachments/assets/28cb370f-5416-4c70-a797-3480b8c3f8a2" />


**Observed result:** `yes` for `tenant-a`, `no` for `tenant-b`.

**Security interpretation:** The RoleBinding grants the `app-a` service account `get` access to secrets only within its own namespace. The authorization check confirms it cannot read Tenant B's secret — RBAC enforces the storage/secret isolation boundary between tenants, even though both secrets exist on the same shared cluster.

## Task 6 — Data Remanence and Secure Deletion

### Procedure

```bash
docker run --rm -v ccse-vol:/data alpine sh -c \
  'echo SENSITIVE-PATIENT-RECORD > /data/phi.txt; sync; rm /data/phi.txt; \
  grep -a SENSITIVE /data/* 2>/dev/null; echo scan-done'

docker run --rm -v ccse-vol:/data alpine sh -c \
  'echo SENSITIVE > /data/phi2.txt; sync; \
  dd if=/dev/zero of=/data/phi2.txt bs=1k count=1 conv=notrunc; rm /data/phi2.txt; \
  echo wiped'
```

<img width="741" height="679" alt="Task 6" src="https://github.com/user-attachments/assets/32b9578c-21fe-41db-8774-d515c8fe7f12" />


**Observed result:** The remanence scan completed with `scan-done` and no visible match returned by `grep` against the remaining files in the volume. The secure-wipe step reported `1024 bytes (1.0KB) copied` followed by `wiped`.

**Security interpretation:** A normal `rm` only removes the filesystem's reference to a file; the underlying bytes are not guaranteed to be cleared immediately. The absence of a `grep` match here does not by itself prove the data was physically gone — it only shows nothing was recoverable through a plain visible-file scan. Overwriting the file with zeroes via `dd` before deletion is a stronger local mitigation, but on cloud storage (replicated volumes, snapshots, SSD wear-levelling, copy-on-write filesystems), tenants generally cannot reach or overwrite every physical copy. This is why cryptographic erasure — destroying the encryption key rather than the physical bytes — is the practical cloud-native solution, covered further in Lab 3.

## Verification

```bash
kubectl get networkpolicy -A
kubectl describe resourcequota tenant-a-quota -n tenant-a
```

<img width="741" height="679" alt="Verification from Claude" src="https://github.com/user-attachments/assets/e3ef2507-e21d-4a1b-8b7d-2a672883278c" />

**Verified state:** `tenant-b` contains `default-deny-ingress` (age confirms it was applied earlier in the session). `tenant-a-quota` remains in place with hard limits of 5 pods, 1 CPU request, and 512Mi memory request.

## Short-Answer Questions

### Q1. Why can containers in different namespaces reach each other by default, and why is that dangerous in multi-tenant cloud?

Kubernetes namespaces provide logical grouping for organizing resources and scoping RBAC — they are not a network boundary. Unless a NetworkPolicy enforced by the CNI selects a pod, all pods in the cluster share a flat network and can route to one another regardless of namespace. Task 2 demonstrated this directly: a probe from `tenant-a` reached `tenant-b`'s service with `HTTP 200`. In a multi-tenant cloud, this is dangerous because a compromised or malicious workload in one tenant could scan, reach, or exploit another tenant's services, enabling lateral movement, data exfiltration, or denial of service even though the tenants appear logically separated.

### Q2. Explain the default-deny principle and how your NetworkPolicy implements it.

Default-deny means all traffic is blocked unless a rule explicitly allows it so the opposite of the default-allow behaviour observed in Task 2. The `default-deny-ingress` policy applied in Task 4 uses `podSelector: {}` to select every pod in `tenant-b`, and declares `policyTypes: [Ingress]` with no ingress rules supplied. Since no rule permits anything, Calico denies all inbound connections to `tenant-b`'s pods. This is confirmed by the same probe that returned `HTTP 200` in Task 2 returning `HTTP 000` after the policy was applied.

### Q3. How do virtual machines and containers differ in isolation strength? When would you add a VM boundary?

Virtual machines run on separate guest kernels behind a hypervisor, giving each VM a hardware-level isolation boundary and a kernel exploit or crash in one VM does not directly affect another. Containers isolate processes using OS-level features (namespaces, cgroups) but **share the host kernel**, so a kernel-level vulnerability or container escape can potentially affect every container on that host. A VM boundary should be added when tenants are mutually untrusted (e.g. a multi-tenant SaaS running customer-supplied code), when regulatory requirements (PCI-DSS, HIPAA) demand hardware-level separation, or whenever the risk of a kernel-level compromise is unacceptable.

### Q4. What is data remanence, and why is cryptographic erasure the preferred cloud solution?

Data remanence is the residual presence of data on a storage medium after it has been "deleted," since normal deletion typically only removes the filesystem reference rather than overwriting the underlying bytes. Task 6 illustrated this concept: `rm` alone does not guarantee the data is gone. In the cloud, cryptographic erasure and destroying the encryption key used to protect the data, rather than the physical storage blocks it is preferred because tenants have no direct access to physical hardware, data is typically replicated across multiple disks/regions/snapshots that cannot all be manually overwritten, and destroying the key renders all remaining copies of the ciphertext computationally unreadable without needing to touch the physical media at all.

### Q5. Which of the three isolation dimensions (compute, network, storage) did each task exercise?

| Task | Isolation Dimension | Evidence / Control |
|------|---------------------|---------------------|
| Task 1 | Compute | Separate namespaces and deployments on one shared cluster |
| Task 2 | Network | Demonstrated default-open cross-namespace access (`HTTP 200`) |
| Task 3 | Compute | ResourceQuota constrained Tenant A's shared CPU/memory/pod capacity |
| Task 4 | Network | Default-deny NetworkPolicy blocked cross-tenant traffic (`HTTP 200` → `HTTP 000`) |
| Task 5 | Storage | Namespace-scoped RBAC allowed own-tenant, denied cross-tenant secret access |
| Task 6 | Storage | Normal deletion vs. overwrite-before-delete; data remanence and cryptographic erasure |

## Security Best-Practices Checklist

- [x] Tenants are separated into distinct namespaces.
- [x] A default-deny NetworkPolicy blocks cross-tenant traffic (verified before/after: `HTTP 200` → `HTTP 000`).
- [x] Resource quotas prevent a noisy-neighbour from exhausting shared capacity.
- [x] Per-tenant secrets are unreadable by other tenants (RBAC enforced: `yes`/`no`).
- [x] Secure deletion / cryptographic erasure is understood for data remanence.

## Cleanup

```bash
kind delete cluster --name ccse-lab2
docker volume rm ccse-vol
```

## Conclusion

This lab demonstrated that logical namespace separation alone does not secure a shared Kubernetes cluster: Tenant A initially reached Tenant B's service without restriction (`HTTP 200`). A Calico-enforced default-deny NetworkPolicy closed that gap (`HTTP 000`), a ResourceQuota reduced noisy-neighbour risk, and namespace-scoped RBAC prevented cross-tenant secret access (`yes`/`no`). The data remanence exercise further showed that ordinary deletion does not guarantee data is unrecoverable, motivating the use of cryptographic erasure as the practical cloud-native approach to secure deletion.
