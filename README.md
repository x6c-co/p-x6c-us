# p.x6c.us

A small text pastebin. Pastes are encrypted before they are stored in rqlite,
with a data key protected by [rypt.dev](https://rypt.dev). Anyone can create a
paste; anyone with its link can read it until it expires.

- Text only (UTF-8, no NUL bytes), up to 256 KiB.
- Expiry of 10 minutes, 1 hour, 1 day (default), 1 week or 30 days.
- Optional delete-after-first-view.
- Paste IDs are UUIDv4 by default; ULID and short random IDs are available.

## Using it

In a browser, open https://p.x6c.us/, paste, and pick an expiry.

From a terminal:

```sh
curl --data-binary @notes.txt 'https://p.x6c.us/api/paste?expiry=1w'
# -> https://p.x6c.us/<id>   (201 Created, also in the Location header)

curl https://p.x6c.us/raw/<id>          # the text, exactly as sent
some-command | curl --data-binary @- 'https://p.x6c.us/api/paste?burn=1'
```

`expiry` is one of `10m`, `1h`, `1d`, `1w`, `30d` (default `1d`). `burn=1`
deletes the paste the first time it is read.

A delete-after-first-view paste opened in a browser first shows a "View and
delete" button, because link previews (Slack, iMessage, scanners) fetch links
with GET and would otherwise burn it. `/raw/<id>` does not ask: reading it
from a terminal is the view.

Creating pastes is limited per client IP (per /64 for IPv6): 10 at once, then
one every 2 minutes.

## How encryption works

```
            create / read paste                     startup only
browser ──> p ──AES-256-GCM(data key)──> rqlite     p ──unwrap──> rypt.dev
```

1. On first start, `p` asks rypt to `wrap` a new 32-byte **data key** and
   stores only the wrapped form, in rqlite (`paste_data_keys`). The AAD
   `p-x6c-us/data-key/<key id>` binds it to its row.
2. On every start, `p` asks rypt to `unwrap` each stored data key. That is the
   only time rypt is called: about one rypt operation per key per restart.
3. Each paste is sealed locally with AES-256-GCM under the newest data key,
   with a random 96-bit nonce and the AAD `p-x6c-us/paste/<paste id>`, so
   ciphertext moved to another paste's row will not open. Only the key ID,
   nonce and ciphertext are stored (`pastes`).

Paste text never goes to rypt, and creating or reading a paste never waits on
it. If rypt is down, running pods carry on; new pods cannot start.

### What this protects against, and what it doesn't

It protects pastes from anyone who can read rqlite but not the cluster's
Secrets: rqlite's volumes and snapshots, backups of them, and rqlite's HTTP
API, which has no authentication inside the cluster.

It does not protect against someone with access to the cluster's Secrets,
because the rypt API key is one of them and can unwrap the data key. Nor does
it hide pastes from this service: the server sees the text. (A pastebin that
encrypts in the browser, with the key in the URL fragment, would; this one
doesn't.)

### Deleted pastes

Expired pastes are deleted by a sweep every minute, and are never served once
past their expiry. A deleted paste's ciphertext can remain in rqlite's Raft log
and snapshots until they are compacted, but it stays encrypted there.

## Configuration

All configuration is through environment variables.

| Variable | Default | |
|---|---|---|
| `P_RYPT_KEY_ID` | (required) | rypt key UUID |
| `P_RYPT_TOKEN` | (required) | rypt API key, `ry_…` |
| `P_RYPT_URL` | `https://api.rypt.dev` | |
| `P_RQLITE_URL` | `http://rqlite.rqlite.svc.cluster.local` | |
| `P_BASE_URL` | `https://p.x6c.us` | used in links handed out |
| `P_LISTEN` | `:8080` | |
| `P_ID_FORMAT` | `uuid` | `uuid` (v4), `ulid` or `short` |
| `P_ID_SHORT_LENGTH` | `12` | length of `short` IDs, 8–64 |
| `P_MAX_PASTE_BYTES` | `262144` | |
| `P_CREATE_BURST` | `10` | pastes a client may create at once |
| `P_CREATE_EVERY` | `2m` | then one per this interval |
| `P_TRUST_PROXY` | `false` | take the client IP from `X-Real-Ip`; set only behind a proxy that overwrites it, as Traefik does |

Changing `P_ID_FORMAT` only affects new pastes; links of every format keep
working. ULIDs, unlike the other two, reveal when the paste was created to
anyone holding the link. `short` IDs carry about 6 random bits per character,
so keep them at 10 or more.

## Deploying (Vultr VKE)

The cluster runs rqlite, Traefik and cert-manager (see the opskit repo).
`deploy/k8s/p.yaml` has everything else apart from two Secrets in namespace
`p`, which you create once by hand:

```sh
export KUBECONFIG=~/.kube/vultr-config

# rypt: create a key and an API key in https://dashboard.rypt.dev/
kubectl -n p create secret generic p-rypt \
  --from-literal=P_RYPT_KEY_ID=<key uuid> \
  --from-literal=P_RYPT_TOKEN=<ry_… api key>

# GHCR: a GitHub token with read:packages, since the image is private
kubectl -n p create secret docker-registry ghcr-pull \
  --docker-server=ghcr.io --docker-username=<github user> \
  --docker-password=<token>

kubectl apply -f deploy/k8s/p.yaml
```

DNS: `p.x6c.us` needs A records for the node IPs (Traefik listens on 80/443 on
every node). cert-manager issues the certificate once the name resolves.

### Releasing

Push a `v*` tag; `build-ghcr` builds and pushes `ghcr.io/x6c-co/p-x6c-us:<tag>`.
Then set that tag in `deploy/k8s/p.yaml` and apply it.

### Rotating the data key

```sh
kubectl -n p exec deploy/p -- /p rotate-key
kubectl -n p rollout restart deploy/p
```

Restarted pods seal new pastes with the new key; older pastes stay readable
under the old one, which is kept.

## Development

```sh
go test ./...
```

The `store` tests need a running rqlite and are skipped without one. Run them
against a throwaway instance with foreign keys on, as the cluster's is:

```sh
rqlited -fk=true -http-addr 127.0.0.1:4001 -raft-addr 127.0.0.1:4002 /tmp/rqlite-test &
P_TEST_RQLITE_URL=http://127.0.0.1:4001 go test ./...
```

CI (`.github/workflows/ci.yml`) runs golangci-lint, `go vet`, govulncheck and
the full test suite against rqlite.
