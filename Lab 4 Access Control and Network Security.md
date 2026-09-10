# Lab 4: Access Control & Network Security

**Course:** IKB42603 Cloud Computing Security Essentials
**Name:** _(fill in your full name as printed in Lab 2)_
**Lecturer:** _(confirm — Lab 2 used "MADAM ADNI"; lab manual header PDF shows "Prof. Dr. Shahrulniza Musa")_
**Section:** B03, Group S
**Date:** _(submission date)_

## Objectives

This lab demonstrates access control and network security across four dimensions:

1. **Authentication (AuthN)** — verifying identity via HTTP Basic auth.
2. **Multi-factor authentication** — adding a TOTP second factor.
3. **Authorization (AuthZ)** — enforcing least-privilege permissions with Kubernetes RBAC.
4. **Network segmentation, firewalling and host hardening** — limiting what a compromised component can reach or exploit.

**Environment note:** Completed on macOS (zsh) with Docker Desktop, kind, kubectl, and `oath-toolkit` (installed via Homebrew). Several environment-specific issues were encountered and resolved — documented under the relevant tasks below.

## Task 1 — Authentication: a Password-Protected Service

### Procedure
```bash
docker run --rm httpd:alpine htpasswd -nb student 'P@ssw0rd!' > htpasswd.txt

mkdir -p html
echo "Authenticated OK" > html/index.html

cat > default.conf <<'EOF'
server {
    listen 80;
    root /usr/share/nginx/html;
    index index.html;
    location / {
        auth_basic "Restricted";
        auth_basic_user_file /etc/nginx/.htpasswd;
    }
}
EOF

docker run --rm -d --name authsvc -p 8080:80 \
 -v $(pwd)/default.conf:/etc/nginx/conf.d/default.conf \
 -v $(pwd)/htpasswd.txt:/etc/nginx/.htpasswd \
 -v $(pwd)/html:/usr/share/nginx/html \
 nginx

curl -s -o /dev/null -w 'no-creds: %{http_code}\n' http://localhost:8080
curl -s -u student:'P@ssw0rd!' http://localhost:8080
```

`[SCREENSHOT: Task 1 — 401 (no creds) followed by "Authenticated OK" (valid creds)]`

**Observed result:** A request without credentials was rejected with `401`; the same request with valid credentials (`student` / `P@ssw0rd!`) returned `200 Authenticated OK`.

**Security interpretation:** HTTP Basic authentication (`auth_basic`) requires a valid username/password pair, checked against a `.htpasswd` credential file, before nginx will serve the protected location. This is a minimal example of **authentication** — proving *who* is making the request — as distinct from authorization, which is addressed separately in Task 3.

**macOS-specific issue and fix:** The manual's approach of returning a fixed string directly from the `location` block (`return 200 '...';`) alongside `auth_basic` in the same block did not enforce authentication — every request, with or without credentials, returned `200`. This is a known nginx behaviour: the `return` directive executes during the early **rewrite phase**, while `auth_basic` is checked during the later **access phase**, so the response is sent before the auth check ever runs. The fix was to serve a real static file (`index.html`) via nginx's normal `root`/`index` directive path instead of `return`, which correctly routes the request through the access phase first.

## Task 2 — Multi-Factor Authentication (TOTP)

### Procedure
```bash
SECRET=$(python3 -c "import os, base64; print(base64.b32encode(os.urandom(20)).decode())")
echo "Enrol this secret in an authenticator app: $SECRET"

CODE=$(oathtool --totp -b "$SECRET")
echo "Code generated: $CODE"
[ "$CODE" = "$(oathtool --totp -b "$SECRET")" ] && echo 'MFA OK' || echo 'MFA FAILED'
```

`[SCREENSHOT: Task 2 — secret + generated code + MFA OK]`

**Observed result:** A random base32 secret was generated, a valid 6-digit TOTP code was produced from it, and re-validating that code against a freshly generated one returned `MFA OK`.

**Security interpretation:** TOTP combines something the user knows (their password, from Task 1) with something the user has (the shared secret, normally held in an authenticator app). Because the code rotates every 30 seconds, a captured or intercepted code is only briefly usable, which defeats most credential-based attacks (phishing, credential stuffing, password reuse) that rely on a stolen password alone remaining valid indefinitely.

**macOS-specific issue and fix:** The manual's `base32` command is not available on macOS (it is a GNU coreutils utility, not part of the BSD toolset shipped with macOS). This was worked around using Python's built-in `base64` module (`python3 -c "...base64.b32encode..."`) to generate an equivalent base32-encoded secret without needing to install additional packages.

## Task 3 — Authorization: RBAC Roles

### Procedure
```bash
kind create cluster --name ccse-lab4
kubectl create namespace app
kubectl create serviceaccount dev -n app
kubectl create role dev-role -n app --verb=get,list --resource=pods
kubectl create rolebinding dev-rb -n app --role=dev-role --serviceaccount=app:dev

SA=system:serviceaccount:app:dev
kubectl auth can-i list pods -n app --as=$SA
kubectl auth can-i create deploy -n app --as=$SA
kubectl auth can-i delete pods -n app --as=$SA
```

`[SCREENSHOT: Task 3 — three can-i results: yes / no / no]`

**Observed result:** The `dev` service account was permitted to list pods (`yes`) but denied both creating deployments and deleting pods (`no`, `no`).

**Security interpretation:** This demonstrates **authorization** — once identity is established (Task 1's authentication, or in Kubernetes, the service account), a Role/RoleBinding pair determines exactly which verbs on which resources that identity may exercise. The `dev-role` was scoped to only `get`/`list` on `pods`, so the RBAC system correctly denied both a broader read action (listing deployments was never granted) and any write/delete action, enforcing least privilege.

**Session A complete.** `docker stop authsvc` was run before proceeding.

## Task 4 — Network Segmentation (Three-Tier)

### Procedure
```bash
docker network create frontend-net
docker network create backend-net

docker run -d --name db --network backend-net redis:alpine
docker run -d --name app --network backend-net nginx
docker network connect frontend-net app
docker run -d --name web --network frontend-net nginx

docker exec web sh -c 'apt-get update -qq && apt-get install -y -qq curl > /dev/null; curl -s -m 3 db:6379 || echo BLOCKED'
docker exec app sh -c 'apt-get update -qq && apt-get install -y -qq netcat-openbsd > /dev/null; nc -z -w3 db 6379 && echo REACHABLE'
```

`[SCREENSHOT: Task 4 — web→db BLOCKED, app→db REACHABLE]`

**Observed result:** `web` (on `frontend-net` only) could not reach `db` (`BLOCKED`). `app` (connected to both `frontend-net` and `backend-net`) successfully reached `db` (`Connection...succeeded! REACHABLE`).

**Security interpretation:** Placing the database only on `backend-net` means it is unreachable from any container that is not also attached to that network. Even if the internet-facing `web` tier were compromised, the attacker cannot pivot directly to the data tier — network segmentation contains lateral movement, one of the core defence-in-depth principles in cloud architecture.

**macOS-specific note:** The manual's `nginx` and `apk` commands assumed an Alpine-based nginx image; the current `nginx:latest` image is Debian-based, so package installation was adapted to `apt-get install -y -qq curl` / `apt-get install -y -qq netcat-openbsd` in place of `apk add curl`.

## Task 5 — Firewall Rules (Default-Deny)

### Procedure
```bash
docker run --rm --cap-add=NET_ADMIN alpine sh -c '\
 apk add -q iptables; \
 iptables -P INPUT DROP; \
 iptables -A INPUT -p tcp --dport 443 -j ACCEPT; \
 iptables -A INPUT -i lo -j ACCEPT; \
 iptables -L INPUT -n'
```

`[SCREENSHOT: Task 5 — iptables ruleset showing policy DROP + ACCEPT rules]`

**Observed result:**
```
Chain INPUT (policy DROP)
target     prot opt source               destination
ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:443
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0
```

**Security interpretation:** The default policy is `DROP` — every inbound connection is rejected unless explicitly permitted. Only two exceptions were carved out: TCP port 443 (HTTPS) and loopback traffic. This mirrors the security-group model used by cloud providers (AWS, Azure, GCP): nothing is reachable by default, and each open port is a deliberate, auditable decision rather than an accidental exposure.

## Task 6 — Container / Host Hardening

### Procedure
```bash
docker run -d --name hardened \
 --user 1000:1000 \
 --read-only \
 --cap-drop=ALL \
 --security-opt no-new-privileges \
 --tmpfs /tmp \
 nginxinc/nginx-unprivileged

docker inspect hardened --format 'User={{.Config.User}} ReadOnly={{.HostConfig.ReadonlyRootfs}}'

docker run --rm aquasec/trivy image --severity HIGH,CRITICAL nginx:alpine | head -20
```

`[SCREENSHOT: Task 6 — inspect output (User=1000:1000 ReadOnly=true) + Trivy Report Summary (Total: 7, HIGH: 7, CRITICAL: 0)]`

**Observed result:** `docker inspect` confirmed the container runs as non-root UID `1000:1000` with a read-only root filesystem. A Trivy scan of `nginx:alpine` reported 7 HIGH-severity and 0 CRITICAL vulnerabilities.

**Security interpretation — three hardening measures applied:**

| Measure | Attack surface it removes |
|---|---|
| `--user 1000:1000` (non-root) | Blocks privilege escalation to root if the container process is compromised; an exploited process only has an unprivileged user's permissions |
| `--read-only` root filesystem | Prevents an attacker from writing malware, modifying binaries, or persisting changes inside the container filesystem |
| `--cap-drop=ALL` | Removes all Linux capabilities (e.g. `CAP_NET_RAW`, `CAP_SYS_ADMIN`) by default, blocking kernel-level actions an exploited process could otherwise attempt |

The Trivy scan is a separate but complementary control: it identifies known vulnerabilities (CVEs) in the base image's packages *before* deployment, so patching decisions can be made proactively rather than reactively.

## Verification

```bash
kubectl get rolebinding dev-rb -n app -o yaml
docker inspect hardened --format '{{json .HostConfig.CapDrop}}'
```

`[SCREENSHOT: verification commands output]`

## Short-Answer Questions

### Q1. Explain the difference between authentication and authorization using Tasks 1 and 3.

Authentication answers "who are you?" — Task 1 demonstrated this with HTTP Basic auth, where the server verified the caller's identity (`student` / `P@ssw0rd!`) before granting any access at all, returning `401` for anyone who could not prove who they were. Authorization answers "what are you allowed to do, now that I know who you are?" — Task 3 demonstrated this at a finer grain: the `dev` service account's *identity* was never in question (it authenticated to the cluster automatically as itself), but RBAC decided that this identity could `list` pods but could not `create` deployments or `delete` pods. In short, authentication is a one-time identity check at the door; authorization is a continuous, per-action permission check once inside.

### Q2. Why is MFA so effective, and which attacks does it defeat?

MFA requires two independent factors from different classes — typically something the user knows (a password) and something the user has (a TOTP-generating device or app). Because Task 2's code changes every 30 seconds, even if an attacker obtains the password through phishing, credential stuffing, or a data breach, they cannot authenticate without also possessing the physical device generating the current code. This defeats the large majority of credential-only attacks, since compromising a static secret (a password) is far easier than compromising a synchronized, time-limited, device-bound value.

### Q3. How does network segmentation limit the damage of a compromised web server?

In Task 4, the `web` container — representing the internet-facing tier — was placed only on `frontend-net` and had no route to `db` on `backend-net`, confirmed by the `BLOCKED` result. If an attacker were to compromise the `web` service (the most exposed component, since it accepts public traffic), segmentation means they cannot pivot directly to the database from that foothold. They would need to compromise a second component (like `app`, which bridges both networks) before reaching sensitive data — segmentation does not prevent every attack, but it forces additional steps and increases the chance of detection before real damage occurs.

### Q4. What does a default-deny firewall policy achieve, and how does it relate to cloud security groups?

A default-deny policy (Task 5's `iptables -P INPUT DROP`) rejects all inbound traffic unless a rule explicitly allows it, rather than the reverse (default-allow with explicit blocks). This means any port or service not deliberately opened is automatically unreachable, closing off accidental exposure from misconfigurations, forgotten services, or ports opened during testing. This is precisely the model cloud security groups use: an AWS/Azure/GCP security group starts with no inbound access, and every rule an operator adds is a conscious, auditable exception — least privilege applied to the network layer.

### Q5. List the hardening measures you applied and the attack surface each one removes.

Three measures were applied in Task 6:
- **`--user 1000:1000`** (run as non-root) — removes the ability for a compromised process to gain root-level control of the container, limiting the blast radius of a container escape or code-execution exploit.
- **`--read-only`** (read-only root filesystem) — removes the ability to write persistent malware or modify application binaries inside the running container, since only the explicitly mounted `--tmpfs /tmp` is writable.
- **`--cap-drop=ALL`** (drop all Linux capabilities) — removes kernel-level privileges (e.g. raw socket access, module loading, ptrace) that an exploited process might otherwise use to escalate further or interact with the host.

Complementing these, the Trivy scan (7 HIGH vulnerabilities found in `nginx:alpine`) identifies known, already-patched CVEs in the base image — reducing the attack surface further by informing whether the base image should be updated before deployment.

## Security Best-Practices Checklist

- [x] Service requires authentication (unauthenticated requests rejected — `401`).
- [x] MFA / second factor implemented and validated (`MFA OK`).
- [x] Authorization enforced by RBAC (least privilege; unauthorised actions denied — `no`/`no`).
- [x] Network segmented so the data tier is unreachable from the front tier (`BLOCKED`).
- [x] Default-deny firewall with explicit allow rules (`policy DROP` + port 443 ACCEPT).
- [x] Container hardened: non-root, minimal, capabilities dropped, read-only; image scanned (Trivy).

## Cleanup

```bash
docker rm -f authsvc web app db hardened 2>/dev/null
docker network rm frontend-net backend-net 2>/dev/null
kind delete cluster --name ccse-lab4
```

## Conclusion

This lab worked through the full identity-and-access chain: authentication (Task 1) established who the caller was, MFA (Task 2) strengthened that proof with a second, time-bound factor, and RBAC (Task 3) then governed what the now-identified caller could actually do. Session B shifted from *who gets in* to *what they can reach*: network segmentation (Task 4) confined a compromised front-tier component from directly reaching the data tier, a default-deny firewall (Task 5) closed off every port not explicitly needed, and container hardening plus vulnerability scanning (Task 6) reduced what an attacker could do even after landing inside a container. Together, these controls repeatedly apply the same underlying principle across different layers — the cloud/network security tip given at the start of the lab: *are you who you claim, and are you allowed to do this?*
