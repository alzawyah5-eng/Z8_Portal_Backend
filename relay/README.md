# PhotonPay static IP relay

PhotonPay can restrict API calls to allowlisted IPv4 addresses. NestJS API
have no fixed outbound IP, so every provider call is forwarded through this small
relay instead and PhotonPay sees only the relay's address.

`server.mjs` is the whole relay. Node 20+, no dependencies.

## 1. Server with a fixed IPv4

Create the smallest instance at Hetzner, DigitalOcean or Lightsail (roughly
$4–6/month), Ubuntu 24.04. Note its **public IPv4** address — that is the value
you allowlist at PhotonPay. Do not put Cloudflare in front of it: the point is
that PhotonPay sees this server's address.

## 2. Install and run

```bash
sudo apt update && sudo apt install -y nodejs
sudo mkdir -p /opt/photonpay-relay
sudo cp server.mjs /opt/photonpay-relay/server.mjs

openssl rand -hex 32          # copy this value, it is RELAY_SECRET
sudo tee /etc/systemd/system/photonpay-relay.service >/dev/null <<'EOF'
[Unit]
Description=PhotonPay static IP relay
After=network.target

[Service]
Environment=PORT=8787
Environment=RELAY_SECRET=PASTE_THE_GENERATED_SECRET
ExecStart=/usr/bin/node /opt/photonpay-relay/server.mjs
Restart=always
User=nobody

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now photonpay-relay
```

Confirm the address PhotonPay will see:

```bash
curl -s -H "x-relay-secret: $RELAY_SECRET" localhost:8787/health
```

`GET /health` requires the same `x-relay-secret` header as `/forward`: without
it the relay answers 404, so the outbound IP, version and configuration are
never handed to an unauthenticated caller.

## 3. HTTPS

The API calls the relay over HTTPS, so terminate TLS on the same box. Caddy is the
shortest path:

```bash
sudo apt install -y caddy
sudo caddy reverse-proxy --from relay.example.com --to 127.0.0.1:8787
```

Point a DNS record for `relay.example.com` at the server's IPv4 first. Certificate
provisioning is automatic.

## 4. Connect the app

In the Z8 app secrets:

- `PHOTONPAY_RELAY_URL` = `https://relay.example.com` (no trailing slash, no path)
- `PHOTONPAY_RELAY_SECRET` = the `RELAY_SECRET` value from step 2

Then at PhotonPay: add the server's IPv4 to the allowlist, remove the Cloudflare
IPv6 entry, and confirm.

## 5. Verify

Connections → **Full diagnostic check**. The relay should read *Reachable*, its
`outbound_ip` is the address to allowlist, and the token probe should return
`code 0000`.

If the relay is unreachable but `curl` works locally, the shared secret does not
match, or the server is not reachable on 443 from the internet.

## Behaviour

- Accepts only `POST /forward` and `GET /health`.
- Requires the `x-relay-secret` header on both; comparison is constant-time.
  An unauthenticated `/health` is indistinguishable from an unknown path (404).
- Forwards only to `x-api.photonpay.com` and `x-api.sandbox.photontech.cc`.
- Passes through `authorization`, `content-type`, `x-pd-token`, `x-pd-sign`,
  `x-pd-authorization` and nothing else.
- Never writes bodies, tokens or credentials anywhere.
- Body capped at 9 MB (ID photo uploads); upstream timeout 25s.
- Since 1.1.0, binary bodies (cardholder ID photos) are accepted Base64-encoded in
  `body_base64` and forwarded byte for byte. Z8 refuses ID photo uploads through an
  older relay, so after updating `server.mjs` restart it:
  `sudo systemctl restart photonpay-relay`.
