# MHR-CFW

### MITM Domain-Fronted HTTP Relay + Cloudflare Worker Exit

[![GitHub](https://img.shields.io/badge/GitHub-MHR_CFW-red?logo=github)](https://github.com/denuitt1/mhr-cfw)


| [English](README.md) | [Persian](README_FA.md) |
| :---: | :---: |

---

## How It Works

### 1 - GAS + Cloudflare Worker Exit
```
Client -> Local Relay -> Google/CDN Front -> GAS (Google Apps Script) Relay -> Cloudflare Worker -> Exit
            |
            +-> Shows www.google.com to network DPI filter
```

### 2 - GAS + Cloudflare Worker Middle + Self-Hosted Upstream Forwarder Relay Exit
```
Client -> Local Relay -> Google/CDN Front -> GAS (Google Apps Script) Relay -> Cloudflare Worker -> Self-Hosted Upstream Forwarder -> Exit
            |
            +-> Shows www.google.com to network DPI filter
```

In normal use, the browser sends traffic to the proxy running on your computer.
The proxy sends that traffic through Google-facing infrastructure so the network only sees an allowed domain such as `www.google.com`.
Your deployed relay then fetches the real website through cloudflare worker and sends the response back through the same path.

This means the filter sees normal-looking Google traffic, while the actual destination stays hidden inside the relay request.


--- 

## How to Use

### 1 - Download project and extract 

```bash
git clone https://github.com/denuitt1/mhr-cfw.git
cd mhr-cfw
pip install -r requirements.txt
```
> **Can't reach PyPI directly?** Use this mirror instead:
> ```bash
> pip install -r requirements.txt -i https://mirror-pypi.runflare.com/simple/ --trusted-host mirror-pypi.runflare.com
> ```


### 2 - Set Up the Cloudflare Worker (worker.js)

1. Open [Cloudflare Dashboard](https://dash.cloudflare.com/) and sign in with your Cloudflare account.
2. From the sidebar, navigate to **Compute > Workers & Pages**
3. Click **Create Application**, Choose **Start with Hello World** and click on **Deploy**
4. Click on **Edit code** and **Delete** all the default code in the editor.
5. Open the [`worker.js`](deploy/cloudflare-worker/worker.js) file from this project (under `deploy/`), **copy everything**, and paste it into the Apps Script editor.
6. **Important:** Change the worker on this line to the worker you created:
   ```javascript
   const WORKER_URL = "myworker.workers.dev";
   ```
7. Click **Deploy**.

### 3 - Set Up the Google Relay (Code.gs)

1. Open [Google Apps Script](https://script.google.com/) and sign in with your Google account.
2. Click **New project**.
3. **Delete** all the default code in the editor.
4. Open the [`Code.gs`](deploy/gas/Code.gs) file from this project (under `deploy/`), **copy everything**, and paste it into the Apps Script editor.
5. **Important:** Change the password on this line to something only you know, also replace the worker url with your cloudflare worker:
   ```javascript
   const AUTH_KEY = "your-secret-password-here";
   const WORKER_URL = "https://myworker.workers.dev";
   ```
6. Click **Deploy** → **New deployment**.
7. Choose **Web app** as the type.
8. Set:
   - **Execute as:** Me
   - **Who has access:** Anyone
9. Click **Deploy**.
10. **Copy the Deployment ID** (it looks like a long random string). You'll need it in the next step.

> ⚠️ Remember the password you set in step 3. You'll use the same password in the config file below.

### 4 - Run

Click on the `run.bat` file (on windows) or `run.sh` file (on linux) to start the relay.

If you're running for the first time it will prompt a setup wizard where you have to enter the AUTH_KEY and Google Apps Script Deployment ID.
You should see a message saying the HTTP proxy is running on `127.0.0.1:8085`

### 5 - Usage

We recommend using [v2rayN client](https://github.com/2dust/v2rayn) and configuring a socks5 proxy.

You can also use [FoxyProxy](https://getfoxyproxy.org/)'s [Chrome extension](https://chromewebstore.google.com/detail/foxyproxy/gcknhkkoolaabfmlnjonogaaifnjlfnp?hl=en) or [Firefox extension](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/) to use this proxy in your browser.

### 6 - Test your connection

Open [ipleak.net](https://ipleak.net) in your browser, you should see your ip address set as cloudflare's.

<img width="1454" height="869" alt="image" src="https://github.com/user-attachments/assets/dfd3316d-69b6-4b0e-b564-fdb055dbdafd" />


### 7 - Additional Usage Guides
 
#### Using the Proxy Inside a Virtual Machine
 
When you run a virtual machine (VM), it operates in an isolated network environment separate from the host. By default, the VM cannot directly access services running on `localhost` of the host machine — including this proxy.
 
To fix this, you need to find the gateway IP that your hypervisor assigns to the host, then use it instead of `localhost` when configuring the proxy inside the VM.
 
**Example: VirtualBox (NAT mode)**
 
The host is always reachable from inside the VM at `10.0.2.2`. Set the proxy:
 
```bash
export http_proxy="http://10.0.2.2:8085"
export https_proxy="http://10.0.2.2:8085"
export all_proxy="socks5://10.0.2.2:8085"
```
 
To make this permanent, add the lines above to `~/.bashrc` and run `source ~/.bashrc`.
 
Since this proxy performs SSL inspection, you may see certificate errors. Install the included `ca.crt` to fix them:
 
```bash
sudo cp ca.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates
```
 
---
 
#### Sharing the Proxy Over a Local Network (e.g. Mobile Devices)
 
You can use this proxy on your phone or any other device on the same network — no extra software needed.
 
**1. Find your host IP**
 
```bash
# Windows
ipconfig
 
# Linux / macOS
ip addr
```
 
Look for the IP of the adapter connected to your router (e.g. `192.168.1.8`).
 
**2. Forward the port (Windows only, if the service is bound to localhost)**
 
Run `CMD` as Administrator:
 
```cmd
netsh interface portproxy add v4tov4 listenaddress=192.168.1.8 listenport=8085 connectaddress=127.0.0.1 connectport=8085
netsh advfirewall firewall add rule name="Proxy 8085" dir=in action=allow protocol=TCP localport=8085
```
 
**3. Configure proxy on your phone**
 
Connect your phone to the same Wi-Fi, then set the proxy manually:
- **Host:** your host IP (e.g. `192.168.1.8`)
- **Port:** `8085`
 
On Android: **Settings → Wi-Fi → Modify → Proxy → Manual**  
On iPhone: **Settings → Wi-Fi → (network) → HTTP Proxy → Manual**
 
**4. Install the CA certificate**
 
Transfer `ca.crt` to your phone, then:
 
- **Android:** Settings → Security → Install a certificate → CA certificate
- **iPhone:** Open the file → install profile → Settings → General → About → Certificate Trust Settings → enable it


---

## Optional: Stable Exit IP via Upstream Forwarder

CAPTCHAs (Cloudflare Turnstile/bot challenge, reCAPTCHA, hCaptcha) bind tokens
to the IP that solved the challenge. Cloudflare Workers exit through different
edge IPs per request, so verification on the target site fails even when you
solve the challenge. This optional add-on lets the Worker forward all `fetch()`
calls through a small Node server you run on a VPS with a stable IP — giving
the target site one consistent exit address.

### When you need this

- Sites behind Cloudflare's bot challenge keep looping you back to the challenge page.
- Login forms reject you after solving a reCAPTCHA/hCaptcha.
- You need cookie continuity across requests (e.g. `cf_clearance`).

If you don't hit these, leave it unconfigured — the Worker behaves exactly as before.

### Why a separate server is required

Cloudflare Workers don't expose a stable outbound IP — `fetch()` exits through a rotating pool of Cloudflare edge IPs, which is exactly what breaks IP-bound CAPTCHA tokens. Cloudflare's static-egress options (BYOIP, Egress Workers) are Enterprise-tier, so a small VPS with a static IP is the practical workaround. The forwarder is just a thin proxy that re-issues the `fetch()` from a stable address.

### 1. Deploy the forwarder on a VPS

The reference implementation is [`deploy/upstream-forwarder/upstream_forwarder.js`](deploy/upstream-forwarder/upstream_forwarder.js).
It needs Node 18+ and no dependencies. Run it behind Caddy or nginx with TLS —
the Worker rejects non-HTTPS forwarder URLs.

```bash
# On your VPS (Ubuntu/Debian example):
sudo apt install -y nodejs   # must be 18+
export AUTH_KEY="some-long-random-string-at-least-32-chars"
export PORT=8787
node deploy/upstream-forwarder/upstream_forwarder.js
```

Front it with Caddy for auto-TLS:

```
forwarder.example.com {
    reverse_proxy 127.0.0.1:8787
}
```

Quick smoke test:

```bash
curl -X POST https://forwarder.example.com/fwd \
  -H "x-upstream-auth: $AUTH_KEY" \
  -H "content-type: application/json" \
  -d '{"u":"https://httpbin.org/ip","m":"GET","h":{}}'
```

The decoded response body should show the **VPS's IP**.

### 2. Wire the Worker to the forwarder

In the Cloudflare dashboard → your Worker → **Settings → Variables and Secrets**:

| Name | Type | Value |
|---|---|---|
| `UPSTREAM_FORWARDER_URL` | Secret | `https://forwarder.example.com/fwd` |
| `UPSTREAM_AUTH_KEY` | Secret | the same `AUTH_KEY` you set on the VPS |
| `UPSTREAM_FAIL_MODE` | Variable | `closed` (default) — return 502 on forwarder failure. Use `open` to fall back to direct fetch. |
| `UPSTREAM_TIMEOUT_MS` | Variable (optional) | default `25000` |

Save and redeploy the Worker.

### 3. Verify

Browse `https://httpbin.org/ip` through the proxy — you should see the **VPS's IP**, not Cloudflare's. Then revisit a CAPTCHA-protected site that wasn't working — the challenge should now validate.

> The forwarder must require auth. Without `AUTH_KEY` it refuses to start. Anyone with the URL and key can use it as a relay, so keep both secret.

### 4. Scope the forwarder to specific hosts (optional)

By default every request the Worker handles routes through the forwarder, so unrelated traffic also burns VPS bandwidth. To send only the sites that need a stable exit IP through the VPS, list them in `forwarder_hosts` in `config.json` — same syntax as `bypass_hosts` (exact hostname or `.suffix`). Anything not matched falls back to direct `fetch()` on the Worker.

```json
{
   ...
   "forwarder_hosts": [
       "example.com",
       ".cf-protected-suffix"
   ]
   ...
}
```

Leave the list empty (or remove the key) to keep the historical "forward everything" behavior.

---

## Disclaimer

`MHR-CFW` is provided for educational, testing, and research purposes only.

- **Provided without warranty:** This software is provided "AS IS", without express or implied warranty, including merchantability, fitness for a particular purpose, and non-infringement.
- **Limitation of liability:** The developers and contributors are not responsible for any direct, indirect, incidental, consequential, or other damages resulting from the use of this project or the inability to use it.
- **User responsibility:** Running this project outside controlled test environments may affect networks, accounts, proxies, certificates, or connected systems. You are solely responsible for installation, configuration, and use.
- **Legal compliance:** You are responsible for complying with all local, national, and international laws and regulations before using this software.
- **Google services compliance:** If you use Google Apps Script or other Google services with this project, you are responsible for complying with Google's Terms of Service, acceptable use rules, quotas, and platform policies. Misuse may lead to suspension or termination of your Google account or deployments.
- **License terms:** Use, copying, distribution, and modification of this software are governed by the repository license. Any use outside those terms is prohibited.

---

## Contributors
- Special thanks to [onlymaj](https://github.com/onlymaj)

---

## Sources
- This project is based on [MasterHttpRelayVPN](https://github.com/masterking32/MasterHttpRelayVPN)

---

## License

[MIT](LICENSE)
