# GLNC wired campus auto-login

This project reproduces a Dr.COM / ePortal authentication flow documented through a pcapng capture and the corresponding Portal JavaScript.

## What the capture shows

- The reference capture was collected on an Ethernet interface; its device name is not relevant to the protocol.
- The capture begins after IPv4 configuration already exists; it contains no DHCP/BOOTP exchange, so DHCP is an integration concern rather than an observed part of this trace.
- There are no EAPOL / EAP frames, so this is not an 802.1X supplicant handshake.
- Before authentication, DNS is reachable, HTTPS SYNs are effectively blocked, and ordinary HTTP is transparently intercepted by campus equipment.
- The intercepted HTTP response identifies itself as `NetEngine Server 1.0` and returns a 302 to the campus portal; after authentication the real Internet server responds instead.
- The observed campus Portal is at `192.168.110.1`; this is a private network address, not a credential.
- The redirect carries the current client IPv4, client MAC, AC IP and AC name.
- The page calls `/eportal/portal/page/loadConfig` and `/drcom/chkstatus`.
- In this deployment, login is a GET request to `http://192.168.110.1:801/eportal/portal/login` with Dr.COM ePortal 4.1.3 parameters. The client still extracts the host from the live redirect rather than requiring a fixed address.
- The captured successful response is JSONP with `result=1` and `Portal协议认证成功！`.
- After that request, the browser connectivity probe immediately returns normal 200/204 responses.

The capture's `loadConfig` reports `login_method=1`, `en_md5=0`, `password_cut=0`, and `enable_https=0`. Re-reading the live portal JavaScript confirms that this mode copies the password form value directly to `user_password`; the only transformation on the wire is normal URL percent-encoding. The login request carries no cookie, challenge, CSRF token, or authorization header.

Before every credential-bearing login, this implementation now fetches the live portal page, reads the current ePortal JavaScript, calls `loadConfig`, and verifies that those four protocol settings still match the captured mode. If the school changes authentication mode, the client fails closed instead of guessing a password transform.

## Install

```bash
cd ~/glnc-autologin
sudo ./install.sh
```

The installer stores credentials in `/etc/glnc-autologin.conf` with mode `0600`, installs a NetworkManager dispatcher, and starts one-shot probes for currently active IPv4 interfaces.

On later link-up or DHCP lease changes, NetworkManager starts `glnc-autologin@<iface>.service` for the interface that changed. The interface name is discovered at runtime instead of being hard-coded. The Python client binds both that interface and its current source IPv4, probes it independently, and sends credentials only if that exact interface receives the expected Dr.COM redirect and compatible live Portal profile.

**Authentication can expire without a link-down or DHCP event.** The installer also enables `glnc-autologin-check.timer`. It runs an interface-bound probe every minute, and when it sees a verified GLNC captive-portal redirect, it reauthenticates. If the interface is already online, no credentials are sent. Both triggers share a root-owned file lock to avoid racing duplicate login requests.

When run manually without `--interface`, the client enumerates eligible active physical interfaces with a global IPv4 address. It prefers an interface that is actually behind the captive portal; an already-online interface does not prevent a simultaneously captive interface from being discovered.

## Manual test

To inspect discovered portal parameters without sending credentials:

```bash
sudo python3 ./glnc_autologin.py --config ./glnc-autologin.conf.example --dry-run
```

After installation:

```bash
sudo systemctl start glnc-autologin@YOUR_INTERFACE.service
sudo systemctl status glnc-autologin-check.timer
systemctl list-timers glnc-autologin-check.timer --all
journalctl -t glnc-autologin -n 100 --no-pager
journalctl -u glnc-autologin-check.service -n 100 --no-pager
journalctl -u glnc-autologin@YOUR_INTERFACE.service -n 100 --no-pager
```

Upgrade an existing installation **without prompting for, or overwriting, saved credentials**:

```bash
sudo ./install.sh --upgrade
```

Only copying `glnc-autologin@.service` into `/etc/systemd/system` is insufficient:
the executable, configuration file and NetworkManager dispatcher must also be installed, and
the timer needs to be enabled. The unsuffixed name `glnc-autologin.service` does not exist,
because `glnc-autologin@.service` is a template service.

## Notes

- The recommended credential setting is a full `GLNC_ACCOUNT`, such as `student-id@cmcc`. Carrier choice is part of the user's identity, not something that can be safely inferred from a NIC or DHCP lease. Legacy `GLNC_USERNAME` + optional `GLNC_SUFFIX` is still accepted, but there is no longer an implicit `@cmcc` default.
- Device-specific values are not stored: interface name, client IPv4, client MAC, Portal host, AC IP/name, VLAN/SSID/AP fields when present, ePortal port, JavaScript version, program index, and page index are discovered at runtime.
- Automatic interface discovery prefers connected NetworkManager Ethernet/Wi-Fi devices and ignores container bridges, veth, TUN/TAP, and WireGuard-style virtual links. `--interface` can still explicitly select any special interface when needed.
- `GLNC_EXPECTED_PROGRAM_INDEX` can optionally pin the campus Portal deployment while remaining portable across devices. This is useful because the Portal itself is plain HTTP and therefore has no TLS identity to authenticate.
- The portal host, client IP/MAC, AC IP and AC name are learned from the captive-portal redirect on every run. There are no hard-coded AC fallbacks.
- Before sending credentials, the client requires an `/a79.htm` Dr.COM redirect containing `wlanuserip`, `wlanacip`, `wlanacname`, and `wlanusermac`. `wlanuserip` must match the selected interface's source IPv4. A 12-hex-digit `wlanusermac` is additionally checked against the hardware MAC; longer hexadecimal values are treated as Portal-issued session/anonymous MAC tokens because the live ePortal JavaScript itself stores the query value directly in `term.mac` and reuses it for login.
- The client no longer assumes the vendor bootstrap file is named `a41.js`. It scans the landing page and referenced scripts for the current ePortal port, JavaScript protocol version, and program index; `loadConfig` must then confirm `login_method=1`, `en_md5=0`, `password_cut=0`, and `enable_https=0`.
- The service uses `NoNewPrivileges`, `PrivateTmp`, `ProtectHome`, `ProtectSystem=strict`, and a restrictive umask.
- The script never prints the password and does not spawn another process with credentials in its command line.
- The campus portal itself places the literal password in a plain-HTTP GET query string. `/etc/glnc-autologin.conf` and packet captures of the login must therefore be treated as secrets. The client never prints the generated login URL.
