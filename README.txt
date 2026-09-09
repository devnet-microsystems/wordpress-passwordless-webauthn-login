=== Sovereign AI Overseer ===

Contributors: devnet, freemius
Plugin Name: Sovereign AI Overseer - Enterprise Edition
Requires at least: 6.2
Tested up to: 6.5
Requires PHP: 8.1
Stable tag: 1.5.4
License: Commercial — see EULA.txt
License URI: https://devnet-microsystems.com/eula

Passwordless WordPress login via WebAuthn/FIDO2 biometrics, backed by a 12-word recovery phrase. No user-chosen password is required for authentication.

== Description ==


**Important:** To use the advanced AI features securely, you must deploy your own private Google Cloud Run instance using the included `cloud-run` folder. We do not provide a centrally hosted gateway.

Sovereign AI Overseer replaces WordPress's email + password login with native biometric
authentication (Face ID, Touch ID, Windows Hello, hardware security keys) via the
WebAuthn/FIDO2 standard.

There is no password field anywhere in the registration or login flow. Account
recovery is handled by a single 12-word recovery phrase (drawn from the standard
BIP-39 wordlist), which the user can restore access with either by scanning a QR
code or by typing the words manually.

= Key features =

* **Gemini AI Security Sentinel** — Gemini 3.8 Flash analyzes failed authentication traffic; a deterministic policy gate can quarantine a suspicious source for 15 minutes.
* **Tor / Onion Mode (Proof of Work)** — Optional mode that replaces IP-based rate limiting with a JavaScript cryptographic puzzle, preventing brute-force attacks without banning legitimate Tor exit nodes.
* WebAuthn/FIDO2 registration and login — Face ID, Touch ID, Windows Hello, and
  hardware security keys
* 12-word recovery phrase, generated server-side with a cryptographically secure
  random number generator
* Recovery via QR code (camera scan or image upload) or manual phrase entry —
  both paths verify identically server-side
* Recovery secrets are never stored in plain text: a fast lookup hash plus a
  bcrypt verification hash, both one-way
* Per-account lockout plus deterministic per-IP rate limiting on recovery attempts
* Server-side emergency break-glass access, controlled by a constant in
  wp-config.php — never exposed to the browser
* Minimal admin settings page with license status, live diagnostics, and real-time AI Sentinel logs
* Fully Internationalized (i18n) — Natively supports 150+ languages using WordPress translation standards
* Self-contained: no third-party identity provider, no phone number, no email
  address required to authenticate
* Self-Service Device Management Dashboard via the `[sovauth_devices]` shortcode

= Requirements =

* WordPress 6.2 or later
* PHP 8.1 or later
* **A valid SSL certificate (HTTPS).** WebAuthn will not run in a non-secure
  browsing context. This is a browser-level restriction, not a plugin setting.
* A modern browser/device with platform biometrics or a connected security key

== Installation ==

1. In your WordPress admin, go to **Plugins → Add New → Upload Plugin**.
2. Choose the `sovereign-auth.zip` file and click **Install Now**.
3. Click **Activate**.
4. Confirm your site is served over HTTPS — biometric registration will fail
   silently in the browser otherwise.
5. To allow new users to register, go to **Settings → General** and check the box for **"Anyone can register"**. The plugin will automatically show a "Register" button on the login screen.
6. Visit your login page to confirm the new interface renders, and the
   registration page to create your first biometric account.
7. You can place the `[sovauth_devices]` shortcode on any page to let users manage (view, add, revoke) their biometric devices.
8. Go to **Settings → Sovereign AI Overseer** and configure Gemini. You must deploy your own Cloud Run gateway using the included `cloud-run/` folder and enter its URL and Secret here. Alternatively, use direct Gemini API access as a fallback.

Alternative install via FTP/SFTP: upload the unzipped `sovereign-auth` folder to
`/wp-content/plugins/`, then activate it from the Plugins screen as above.

== Enterprise Cloud Architecture ==

Sovereign AI Overseer supports a **dual-deployment AI architecture** to fit any business model:

1. **Sovereign AI (BYOK - Bring Your Own Key)**: You must deploy your own private gateway using the included `cloud-run` folder. This guarantees total data sovereignty: prompts flow directly from your WordPress server to your private Google Cloud Run instance, never touching our servers. See `cloud-run/README.md` for deployment instructions. We do not provide a centrally hosted gateway.

== AI Sentinel: Active Mitigation Architecture (Layer 7) ==

Sovereign AI Overseer doesn't just passively log attacks; it actively defends the authentication layer in real-time using a deterministic Layer 7 mitigation strategy powered by Google Gemini 3.8 Flash.

1. **Asynchronous Batching**: To protect against DDoS, malicious requests (e.g., brute-force or exploit payloads) are queued into a high-performance WordPress database log (`pending_ai`) rather than processed synchronously.
2. **AI Verdict**: A background cron worker periodically batches these suspicious IPs and queries Gemini 3.8 Flash. If Gemini identifies the payload as malicious, it returns a `blocked` verdict.
3. **Cryptographic IP Quarantine**: The plugin immediately generates a 15-minute cryptographic quarantine token (Transient) for that IP.
4. **Hard Firewall (wp_die)**: At the very beginning of the WordPress load sequence (`init` hook), the plugin intercepts any traffic from the quarantined IP targeting the authentication endpoints and instantly kills the PHP process with a `403 Forbidden` error. The attacker is repelled in milliseconds, protecting the WordPress core and the database from further load.

== Frequently Asked Questions ==

= What happens if a user loses their recovery phrase AND their device? =

They lose access to that account. By design, there is no email-based "forgot
password" flow and no password to reset — the 12-word phrase is the only
account-recovery mechanism. Make sure your users understand this before they
register. See EULA.txt for the full liability disclaimer.

= Does this work over plain HTTP? =

No. WebAuthn is a browser API that refuses to run outside a secure context
(HTTPS), except on `localhost` for local development. This is enforced by the
browser, not by this plugin.

= Can I use this on a non-WordPress site? =

Not with this build. Every part of the plugin is wired directly into
WordPress's user system, session handling, and admin hooks.

= What if the site administrator gets locked out? =

Define `SOVAUTH_EMERGENCY_ACCESS` as `true` in `wp-config.php`. While that
constant is set, none of the plugin's login/registration hooks run at all, and
WordPress's native username/password login renders exactly as it would without
this plugin installed. Remove the constant once normal access is restored.

= Does deleting the plugin remove its data? =

Yes. Deleting (not just deactivating) the plugin from the Plugins screen runs
its uninstaller, which drops the credentials table and removes every related
usermeta key, transient, and option this plugin created.

== Changelog ==

= 1.5.4 (Security Update) =
* **Security Fix**: Addressed multiple prompt injection vulnerabilities in AI Gateway and Sentinel Cron.
* **Security Fix**: Fixed a DOM-based Cross-Site Scripting (XSS) vulnerability in the username suggestion flow.
* **Security Fix**: Mitigated a Cross-Site Request Forgery (CSRF) vulnerability in unauthenticated REST API endpoints.
* **Security Fix**: Resolved a cryptographic flaw in the recovery phrase backup authentication.

= 1.5.3 (Final Polish) =
* **UI/UX Overhaul**: Split the monolithic Admin UI into two dedicated pages ("Dashboard & Logs" and "Settings") for a cleaner Enterprise experience.
* **Sovereign Risk Engine**: Added a dynamic risk scoring system that calculates threat levels in real-time based on database metrics and active quarantines.
* **AI Forensic Analysis**: Introduced a 1-click forensic analysis tool that prompts the AI Sentinel to analyze quarantined IPs and generate an exportable/printable threat-intel report, permanently stored in the Activity Log.
* **GDPR Compliance & Unban**: IPs in quarantine are now cryptographically masked (MD5 hash) in the database. Added a UI to reverse-lookup and manually unban IPs with 1 click.
* **Manual Trigger**: Added a "Force Run Now" capability for the AI Sentinel to instantly execute batch analysis.
* **UI Refinements**: Fixed layout overlaps, widened configuration inputs for better visibility of Cloud Run URLs, and added a toggleable password mask for the Gateway Secret.

= 1.5.2 (Demo Reliability) =
* Fixed the credential-hash schema migration required by WebAuthn registration and authentication on new and upgraded installations.
* Corrected the Ops Center webhook URL to the registered REST endpoint and made gateway-only deployments fully usable by agents and webhooks.
* Added an append-only Sentinel decision event with risk score and deterministic policy metadata for evidence capture.
* Removed misleading “sent”, “logs cleared”, “online”, and countdown states when the underlying action has not occurred.
* Protected manual Sentinel execution with a WordPress nonce.

= 1.5.0 (Initial Enterprise Release) =
* Initial Release (May - August 2026).
* Core Feature: Enterprise AI Ops Center natively integrated into the WordPress admin panel.
* Core Feature: WebAuthn/FIDO2 Passwordless Biometric Gateway.
* Core Feature: Gemini AI Security Sentinel with dynamic IP banning and Threat-Intel analysis.
* Added: Unified High-Performance SQL Activity Log (`wp_sovauth_activity_log`) providing a cryptographically verifiable hash-chain audit trail for both the Security Sentinel and all AI Agents.
* Added: REST API Webhook Endpoint (`/wp-json/sovereign-auth/v1/agent-webhook`) allowing zero-touch background processing of support tickets and marketing tasks via Zapier/Make.com.
* Added: CSV Export capability for the Activity Logs with date-range filtering for enterprise compliance.
* Added: Customizable prompts for the AI Agents, allowing customers to use the included AI Ops Center for their own products/services.
* Added: Full Freemius SDK Integration for B2B license management, sandbox payment processing, and premium updates.
* Added: Shared-secret authentication for the Agent Webhook endpoint.
* Added: Tor / Onion Mode (Proof of Work) cryptographic puzzle to protect against brute-force attacks without banning legitimate Tor exit nodes.
* Added: Full English internationalization (i18n) across all admin and frontend interfaces.

== Disclaimer ==

This software is provided "as is", without warranty of any kind. See EULA.txt
for the full license terms, including the limitation of liability for lost
account access. Use of this plugin constitutes acceptance of those terms.
