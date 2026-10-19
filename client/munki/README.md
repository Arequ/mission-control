# Munki client

Munki has no check-in protocol. These scripts are the small equivalent of what
Zentral and MunkiReport add.

`preflight` sets `ClientIdentifier` to the hardware serial when it is empty.
`postflight` reads `/Library/Managed Installs/missioncontrol.json` and posts
`ManagedInstallReport.plist` to `POST /munki/checkin`. The JSON file is mode
0600 and is not built into the package:

```json
{"server": "https://mc.example", "token": "<enrollment or device token>"}
```

Point Munki's `SoftwareRepoURL` at `https://mc.example/repo`. Send the same
token with `AdditionalHttpHeaders`:

```xml
<key>AdditionalHttpHeaders</key>
<array>
  <string>Authorization: Bearer &lt;token&gt;</string>
</array>
```

Use the serial as the Basic username when you want the enrollment-derived
token (`HMAC-SHA256` of the enrollment secret and `munki-device-v1\n` + serial,
hex encoded). A shared enrollment secret may also be the Basic password, with
username `munki`.

`build-pkg.sh` copies the scripts into a payload. On macOS it runs `pkgbuild`.
The token stays off the package.

Local placeholders used by compose (`example-munki-enrollment-secret`) are not
production secrets.
