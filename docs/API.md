# com.webos.service.nfc — Luna Service API reference

`webos-nfc-adapter` exposes the NFC stack to webOS/LuneOS applications as the
luna-service2 service **`com.webos.service.nfc`**. Under the hood it talks to
[nfcd](https://github.com/sailfishos/nfcd) over D-Bus:

    Android NFC HAL  ──binder──▶  nfcd  ──D-Bus──▶  webos-nfc-adapter  ──LS2──▶  apps

All methods are registered on the root category, so the full method URI is
`luna://com.webos.service.nfc/<method>`.

| Method | Kind | Purpose |
|---|---|---|
| [`getStatus`](#getstatus) | query, subscribable | Daemon/adapter state |
| [`setEnabled`](#setenabled) | operation | Turn NFC on or off (persistent) |
| [`getTagInfo`](#gettaginfo) | query, subscribable | The tag currently in the field, decoded |
| [`writeTag`](#writetag) | operation | Write a single-record NDEF message |
| [`lockTag`](#locktag) | operation | Permanently write-protect a tag |
| [`cloneTag`](#clonetag) | operation | Replay a raw tag dump onto another tag |
| [`readPassport`](#readpassport) | operation | Read an eMRTD chip via BAC |
| [`readPassportPACE`](#readpassportpace) | operation | Read an eMRTD chip via PACE |
| [`addCardEmulationProfile`](#addcardemulationprofile) | operation | Register a fixed-response HCE profile |
| [`removeCardEmulationProfile`](#removecardemulationprofile) | operation | Unregister one HCE profile |
| [`clearCardEmulation`](#clearcardemulation) | operation | Unregister all HCE profiles |
| [`getCardEmulationEvent`](#getcardemulationevent) | query, subscribable | Last reader-confirmed HCE exchange |

## Conventions

**Replies.** Every reply carries `returnValue` (boolean). On failure the reply
is:

```json
{ "returnValue": false, "errorText": "human readable reason" }
```

There is no `errorCode`; `errorText` is the only error detail. Two generic
errors can come back from any method that takes parameters: `"Malformed
json."` (payload didn't parse) and `"Invalid parameters."` (a required field
is missing or has the wrong type).

**Asynchronous methods.** Methods that touch the tag or nfcd (`setEnabled`,
`writeTag`, `lockTag`, `cloneTag`, `readPassport*`, the card-emulation calls)
reply once the underlying nfcd operation finishes, not immediately. Multi
round-trip operations such as a passport read can take a few seconds; keep
the document or tag steady on the antenna until the reply arrives.

**Subscriptions.** `getStatus`, `getTagInfo` and `getCardEmulationEvent`
accept `"subscribe": true` and then push updates using the same payload shape
as the direct reply. The first reply additionally carries
`"subscribed": true|false`; pushed updates do not.

```
luna-send -i -n 5 luna://com.webos.service.nfc/getTagInfo '{"subscribe":true}'
```

**Availability.** nfcd restarting, or not being installed at all, is a normal
state rather than an error: `getStatus` reports `"available": false` and the
service re-attaches when nfcd comes back. Operations attempted meanwhile fail
with an `errorText` such as `"nfcd is not available"`.

## Access control

Methods are split over two ACG groups
(`files/sysbus/webos-nfc-adapter.api.json.in`):

| Group | Trust levels | Methods |
|---|---|---|
| `nfc.query` | `dev`, `oem` | `getStatus`, `getTagInfo`, `getCardEmulationEvent` |
| `nfc.operation` | `dev`, `oem` | every method (the query methods are members of both groups) |

A read-only client (a status indicator, for instance) should request only
`nfc.query`; anything that writes tags, reads documents or drives card
emulation needs `nfc.operation`.

Default grants (`files/sysbus/webos-nfc-adapter.perm.json.in`) give
`nfc.operation` to `com.webos.service.nfc` itself,
`com.webos.surfacemanager-cardshell`, and
`org.webosports.app.settings.nfc-*`. Other clients must request the group
through their own role/permission files, e.g. in an app's `appinfo.json`:

```json
"requiredPermissions": ["nfc.operation"]
```

The service itself runs privileged with trust level `oem`
(`files/sysbus/webos-nfc-adapter.role.json.in`) and is started by systemd as
`webos-nfc-adapter.service`.

---

## getStatus

Reports the state of the daemon and the adapter. Subscribable; an update is
pushed whenever the daemon, adapter or settings state changes (nfcd
appearing/disappearing, NFC toggled, a target entering or leaving the field).

### Parameters

| Name | Type | Required | Description |
|---|---|---|---|
| `subscribe` | boolean | no | Subscribe to state changes |

### Reply

| Name | Type | Description |
|---|---|---|
| `returnValue` | boolean | Always `true` for this method |
| `subscribed` | boolean | First reply only |
| `available` | boolean | nfcd is running and has published an adapter |
| `enabled` | boolean | The persistent user setting (stored by nfcd) |
| `powered` | boolean | The controller is actually up |
| `present` | boolean | A tag or peer is in the field |
| `mode` | number | Current nfcd mode bitmask (see below) |
| `supportedModes` | number | Modes the adapter supports, same bitmask |
| `techs` | number | Supported technologies bitmask (see below) |
| `daemonVersion` | number | nfcd's version code |
| `adapterPath` | string | nfcd D-Bus adapter path, e.g. `"/nfc0"`; omitted while no adapter exists |

Mode bits: `0x01` P2P initiator, `0x02` reader/writer, `0x04` P2P target,
`0x08` card emulation. Tech bits: `0x01` NFC-A, `0x02` NFC-B, `0x04` NFC-F.

### Example

```
luna-send -i -n 2 luna://com.webos.service.nfc/getStatus '{"subscribe":true}'
```

```json
{
    "returnValue": true,
    "subscribed": true,
    "available": true,
    "enabled": true,
    "powered": true,
    "present": false,
    "mode": 2,
    "supportedModes": 15,
    "techs": 3,
    "daemonVersion": 66311,
    "adapterPath": "/nfc0"
}
```

---

## setEnabled

Turns NFC on or off. The setting is persistent across reboots; nfcd stores it.

### Parameters

| Name | Type | Required | Description |
|---|---|---|---|
| `enabled` | boolean | yes | Desired state |

### Reply

`{"returnValue": true}` on success.

### Errors

| `errorText` | Meaning |
|---|---|
| `Invalid parameters.` | `enabled` missing or not a boolean |
| `nfcd settings interface is not available` | nfcd (or its settings service) is not running |
| *(nfcd D-Bus error text)* | The daemon rejected the change |

### Example

```
luna-send -n 1 luna://com.webos.service.nfc/setEnabled '{"enabled":true}'
```

---

## getTagInfo

Reports the tag currently in the field. Subscribable; a subscriber typically
sees three updates per tag: one when the tag arrives (`present` is `true` but
there is no `tag` object yet), one once the tag and its NDEF records have
been read (with the full `tag` object), and one when it is removed. For
MIFARE Classic tags there are additional progress updates, one per sector,
while the sector sweep runs (see [MIFARE Classic tags](#mifare-classic-tags)).

### Parameters

| Name | Type | Required | Description |
|---|---|---|---|
| `subscribe` | boolean | no | Subscribe to tag arrival/data/removal |

### Reply

| Name | Type | Description |
|---|---|---|
| `returnValue` | boolean | Always `true` for this method |
| `subscribed` | boolean | First reply only |
| `present` | boolean | Something is in the field |
| `tag` | object | The decoded tag; absent while there is no tag or it hasn't finished being read |

### The `tag` object

| Name | Type | Description |
|---|---|---|
| `path` | string | nfcd D-Bus object path, e.g. `"/nfc0/tag0"` |
| `present` | boolean | Tag still in the field |
| `technology` | string | `"nfc-a"`, `"nfc-b"`, `"nfc-f"` or `"unknown"` |
| `protocol` | string | `"t1t"`, `"t2t"`, `"t3t"`, `"t4a"`, `"t4b"`, `"nfc-dep"`, `"mifare-classic"` or `"unknown"` |
| `type` | number | nfcd's tag type (`NFC_TAG_TYPE_*` in nfcd's `core/include/nfc_types.h`): `0` unknown, `1` FeliCa, `2` MIFARE Classic (triggers the sector sweep), `4` MIFARE Ultralight / NTAG family |
| `interfaces` | string[] | nfcd D-Bus interfaces the tag implements, e.g. `"org.sailfishos.nfc.TagType2"` |
| `pollParameters` | object | Technology-specific poll data straight from nfcd; byte-array values rendered as hex strings. For NFC-A tags `NFCID1` is the tag UID — what access-badge style uses care about — and `SEL_RES` is the SAK byte |
| `records` | array | Decoded [NDEF records](#ndef-record-objects); empty if the tag has none |
| `rawDataHex` | string | Type 2 tags only: the tag's whole data area as one hex blob, exactly as read. This is the input [`cloneTag`](#clonetag) expects. Omitted if the raw read failed |
| `sectors` | array | MIFARE Classic only, see below |
| `scanning` | boolean | MIFARE Classic only: `true` while the sector sweep is still running |

### NDEF record objects

Every record carries its raw fields; well-known types the service understands
are additionally decoded into friendly fields selected by `kind`.

| Name | Type | Description |
|---|---|---|
| `tnf` | number | Type Name Format (NFCForum-TS-NDEF_1.0 §3.2.6): 0 empty, 1 well-known, 2 media type, 3 absolute URI, 4 external, 5 unknown, 6 unchanged |
| `type` | string | Record type as text, when printable (e.g. `"U"`, `"T"`) |
| `typeHex` | string | Record type, raw hex (always present) |
| `idHex` | string | Record ID, raw hex; only when the record has one |
| `payloadHex` | string | Payload, raw hex (always present) |
| `payloadSize` | number | Payload length in bytes |
| `kind` | string | `"uri"`, `"text"`, `"smartposter"`, `"media"` or `"external"`; absent when the type isn't one the service decodes |

Per-kind extras:

| `kind` | Extra fields |
|---|---|
| `uri` | `uri` (abbreviation prefix already expanded) |
| `text` | `text`, `language`, `utf16` |
| `smartposter` | `records` — a nested array of record objects |
| `media` | `mediaType` (the MIME type); `text` as well for `text/*` payloads |
| `external` | `externalType` |

### MIFARE Classic tags

MIFARE Classic doesn't do NDEF through nfcd, so these tags get a sector sweep
instead: each of the up-to-40 sectors is tried against the well-known public
default keys only (`FFFFFFFFFFFF` factory default, `A0A1A2A3A4A5` MAD,
`D3F7D3F7D3F7` NFC Forum NDEF, `000000000000`) — deliberately not a
key-cracking attempt. A sector keyed with anything else (as any real
transit or payment card will be) is simply left out of the result. Keys that
worked are cached per tag UID for the session, so re-presenting the same tag
re-reads quickly.

The sweep takes a while, so subscribers get a snapshot after every sector
with `"scanning": true`; the final update has `"scanning": false` and the
complete `sectors` array. Each entry:

| Name | Type | Description |
|---|---|---|
| `sector` | number | 0–39 (32+ only on 4K cards) |
| `keyType` | string | `"A"` or `"B"` (the default sweep only tries key A) |
| `key` | string | The key that authenticated, 12 hex digits |
| `blocks` | string[] | The sector's blocks (4, or 16 for sectors 32–39), each 16 bytes as 32 hex digits |

### Example

```
luna-send -i -n 5 luna://com.webos.service.nfc/getTagInfo '{"subscribe":true}'
```

```json
{
    "returnValue": true,
    "subscribed": true,
    "present": true,
    "tag": {
        "path": "/nfc0/tag0",
        "present": true,
        "technology": "nfc-a",
        "protocol": "t2t",
        "type": 4,
        "interfaces": ["org.sailfishos.nfc.Tag", "org.sailfishos.nfc.TagType2"],
        "pollParameters": {
            "SEL_RES": "00",
            "NFCID1": "04a1b2c3d4e580"
        },
        "records": [
            {
                "tnf": 1,
                "type": "U",
                "typeHex": "55",
                "payloadHex": "027765626f732d706f7274732e6f7267",
                "payloadSize": 16,
                "kind": "uri",
                "uri": "https://www.webos-ports.org"
            }
        ],
        "rawDataHex": "04a1b2c3..."
    }
}
```

---

## writeTag

Writes a single-record NDEF message to the tag currently in the field. The
record built depends on `type`:

| `type` | Required | Optional | Record written |
|---|---|---|---|
| `"uri"` | `uri` | — | NFC Forum URI record (`U`); the standard URI abbreviations are applied automatically |
| `"text"` | `text` | `language` (default `"en"`, max 63 chars) | NFC Forum Text record (`T`), UTF-8 |
| `"vcard"` | `name` | `phone`, `email` | `text/vcard` contact record, the same format Android/iOS write for contact sharing |
| `"wifi"` | `ssid` (≤ 32 chars) | `password` (≤ 64 chars), `auth`, `encryption` | Wi-Fi Simple Config credential (`application/vnd.wfa.wsc`, NFCForum-AD-WIFI 1.1) |
| `"bluetooth"` | `macAddress` (`"AA:BB:CC:DD:EE:FF"`) | `deviceName` | Bluetooth SSP OOB pairing record (`application/vnd.bluetooth.ep.oob`, NFCForum-AD-BTSSP 1.1) |

For `"wifi"`, `auth` is one of `Open`/`None`, `WPA`/`WPA-Personal`,
`WPA2`/`WPA2-Personal` (case-insensitive; anything else falls back to mixed
WPA/WPA2-Personal) and `encryption` is one of `None`, `WEP`, `TKIP`, `AES`
(fallback: mixed AES+TKIP).

Only **Type 2** tags (NTAG21x, MIFARE Ultralight and friends — which is what
blank tags almost always are) can be written: writing goes through nfcd's
`org.sailfishos.nfc.TagType2` interface. Anything else returns an error
rather than pretending to work. The tag is acquired for exclusive access for
the duration of the write and released afterwards.

### Reply

`{"returnValue": true}` once the tag has been written.

### Errors

| `errorText` | Meaning |
|---|---|
| `Expected type "uri" with a uri, …` | `type` missing/unknown, or its required field missing |
| `No tag in the field` | Nothing to write to |
| `Only Type 2 tags can be written` | The tag is not Type 2 |
| *(nfcd error text)* | The write itself failed (tag pulled away, write-protected, too small…) |

### Examples

```
luna-send -n 1 luna://com.webos.service.nfc/writeTag \
    '{"type":"uri","uri":"https://www.webos-ports.org"}'

luna-send -n 1 luna://com.webos.service.nfc/writeTag \
    '{"type":"text","text":"hello","language":"en"}'

luna-send -n 1 luna://com.webos.service.nfc/writeTag \
    '{"type":"vcard","name":"Jane Doe","phone":"+31612345678","email":"jane@example.org"}'

luna-send -n 1 luna://com.webos.service.nfc/writeTag \
    '{"type":"wifi","ssid":"MyAP","password":"hunter22","auth":"WPA2","encryption":"AES"}'

luna-send -n 1 luna://com.webos.service.nfc/writeTag \
    '{"type":"bluetooth","macAddress":"00:11:22:33:44:55","deviceName":"My Speaker"}'
```

---

## lockTag

**Permanently** write-protects the Type 2 tag currently in the field by
setting its NFC Forum static lock bits (block 2, bytes 2–3, set to
`FF FF` — which also locks the lock bytes themselves). **There is no way back
from this once it reaches the tag.**

This is the layout shared by the NTAG21x / MIFARE Ultralight family, which
covers the overwhelming majority of writable tags. The dynamic lock area that
larger tags (NTAG216 and up) additionally have past their first ~48 bytes is
not touched, so a very large tag may keep some writable pages.

### Parameters

None.

### Reply

`{"returnValue": true}` once the lock bytes are written.

### Errors

| `errorText` | Meaning |
|---|---|
| `No tag in the field` | Nothing to lock |
| `Only Type 2 tags can be locked` | The tag is not Type 2 |
| `Failed to acquire the tag: …` / `Failed to read the lock block: …` / `Failed to write the lock bytes: …` | The tag went away or refused mid-operation |

### Example

```
luna-send -n 1 luna://com.webos.service.nfc/lockTag '{}'
```

---

## cloneTag

Writes a raw byte blob to the Type 2 tag currently in the field **verbatim**,
with no NDEF re-encoding. The intended input is the `rawDataHex` field from
an earlier [`getTagInfo`](#gettaginfo) reply for the source tag: replaying
the source's bytes exactly round-trips content that re-encoding the decoded
records could subtly change.

### Parameters

| Name | Type | Required | Description |
|---|---|---|---|
| `rawDataHex` | string | yes | The raw (already TLV-wrapped) data area read from the source tag, as hex |

### Reply

`{"returnValue": true}` once written.

### Errors

| `errorText` | Meaning |
|---|---|
| `Expected rawDataHex, the raw byte string read from the source tag` | Missing or not valid hex |
| `No tag in the field` / `Only Type 2 tags can be written` | As for `writeTag` |
| *(nfcd error text)* | The write failed, e.g. the target tag is smaller than the source dump |

### Example

```
luna-send -n 1 luna://com.webos.service.nfc/cloneTag \
    '{"rawDataHex":"04a1b2c3d4e58048000000e1101200 ..."}'
```

---

## readPassport

Reads the tag currently in the field as an ICAO 9303 eMRTD chip (passport or
eID card) using **Basic Access Control**. The chip access keys are derived
from the three fields printed in the document's own machine-readable zone —
proof the caller is physically holding the document, which is exactly what
BAC relies on. Check digits are computed by the service; do not include them.

After the BAC handshake, EF.DG1 (the chip's own copy of the MRZ) is read
under secure messaging and parsed. With `readPhoto`, EF.DG2 (the facial
photo) is read as well — opt-in, since it costs several extra APDU round
trips. Hold the document still against the antenna until the reply arrives.

### Parameters

| Name | Type | Required | Description |
|---|---|---|---|
| `documentNumber` | string | yes | As printed in the MRZ |
| `dateOfBirth` | string | yes | `YYMMDD`, as printed in the MRZ |
| `dateOfExpiry` | string | yes | `YYMMDD`, as printed in the MRZ |
| `readPhoto` | boolean | no | Also read DG2 (default `false`) |

### Reply

| Name | Type | Description |
|---|---|---|
| `returnValue` | boolean | |
| `mrz` | string | The raw MRZ text from DG1, always present on success |
| `documentType`, `issuingState`, `surname`, `givenNames`, `documentNumber`, `nationality`, `dateOfBirth`, `sex`, `dateOfExpiry` | string | Parsed MRZ fields; present only when the MRZ parses as a recognized TD1 (ID card) or TD3 (passport) layout |
| `photoBase64` | string | The DG2 photo, base64; only with `readPhoto` and a readable DG2 |
| `photoFormat` | string | `"jpeg"`, `"bmp"` (JPEG2000 photos are converted to BMP, since the platform's QML stack cannot display JPEG2000) or `"jpeg2000"` if that conversion failed |

### Errors

| `errorText` | Meaning |
|---|---|
| `Expected documentNumber, dateOfBirth and dateOfExpiry (YYMMDD), as printed in the document's MRZ` | Missing parameter |
| `No tag in the field` | No document on the antenna |
| *…document number, date of birth and date of expiry, or this document may need PACE instead of BAC* | The BAC handshake failed: wrong MRZ data, or the document only supports PACE (common on newer EU documents) — use [`readPassportPACE`](#readpassportpace) |

### Example

```
luna-send -n 1 luna://com.webos.service.nfc/readPassport \
    '{"documentNumber":"NX1234567","dateOfBirth":"850712","dateOfExpiry":"330204","readPhoto":true}'
```

---

## readPassportPACE

Same read and same result shape as [`readPassport`](#readpassport), but the
handshake is **PACE** instead of BAC, keyed by the **CAN** (Card Access
Number) printed on the document. This is the path for documents that reject
`readPassport` with a "may need PACE instead of BAC" error. It is a separate
method rather than an automatic fallback because the two need different
input, and the caller — who is holding the document — can see which is
printed on it.

### Parameters

| Name | Type | Required | Description |
|---|---|---|---|
| `can` | string | yes | The Card Access Number printed on the document |
| `readPhoto` | boolean | no | Also read DG2 (default `false`) |

### Reply / Errors

As for [`readPassport`](#readpassport), plus PACE-specific failures such as
the document not exposing usable PACE parameters in EF.CardAccess.

### Example

```
luna-send -n 1 luna://com.webos.service.nfc/readPassportPACE \
    '{"can":"123456","readPhoto":true}'
```

---

## addCardEmulationProfile

Registers a simple host-card-emulation profile under an ISO 7816-5
Application ID. While the profile is active, this device answers a reader
that selects that AID: an empty OK for SELECT, the fixed `payloadHex` bytes
(with `SW 90 00`) for a read-style APDU, and "instruction not supported"
(`SW 6D 00`) for anything else.

Several profiles can be active at once, one per distinct AID — the reader
picks one by selecting it. Re-adding an AID that is already registered
replaces its payload and `implicit` flag. Registering a profile also asks
nfcd to enable card-emulation mode.

This is deliberately **not** a general APDU responder or relay: one fixed
response per profile, so it can serve as something like a personal
access-badge identifier but can never proxy or clone a live card session.
(Host card emulation on its own also does not get you contactless payments —
those need tokenised credentials issued through Visa VTS / Mastercard MDES
and an EMVCo-certified kernel, which are commercial arrangements rather than
missing code.)

### Parameters

| Name | Type | Required | Description |
|---|---|---|---|
| `aidHex` | string | yes | The Application ID readers select, as hex |
| `payloadHex` | string | no | The fixed bytes returned for a read-style APDU once selected |
| `implicit` | boolean | no | Also answer readers that skip an explicit AID-SELECT, i.e. act as the default profile (default `false`) |

### Reply

`{"returnValue": true}` once nfcd has registered the profile.

### Errors

| `errorText` | Meaning |
|---|---|
| `Expected aidHex, the Application ID to register` | Missing or invalid hex |
| `nfcd is not available` | The daemon is not running |
| *(nfcd error text)* | Registration rejected |

### Example

```
luna-send -n 1 luna://com.webos.service.nfc/addCardEmulationProfile \
    '{"aidHex":"f04c756e654f53","payloadHex":"badge-0042","implicit":false}'
```

---

## removeCardEmulationProfile

Unregisters one profile by AID.

| Name | Type | Required | Description |
|---|---|---|---|
| `aidHex` | string | yes | The AID to unregister |

Errors: `Expected aidHex, the Application ID to unregister`, plus nfcd
failures.

```
luna-send -n 1 luna://com.webos.service.nfc/removeCardEmulationProfile \
    '{"aidHex":"f04c756e654f53"}'
```

---

## clearCardEmulation

Unregisters every profile added via `addCardEmulationProfile`. No parameters.

```
luna-send -n 1 luna://com.webos.service.nfc/clearCardEmulation '{}'
```

---

## getCardEmulationEvent

Subscribable. Reports the most recent card-emulation exchange that a reader
confirmed receiving — useful for UI feedback ("badge was read"). Until the
first such exchange, the reply carries only `returnValue`/`subscribed`;
subscribers then get a push per confirmed exchange.

### Parameters

| Name | Type | Required | Description |
|---|---|---|---|
| `subscribe` | boolean | no | Push an update per confirmed exchange |

### Reply

| Name | Type | Description |
|---|---|---|
| `returnValue` | boolean | |
| `subscribed` | boolean | First reply only |
| `aidHex` | string | Which profile's AID was read; absent until the first exchange |
| `ok` | boolean | nfcd reports the response as successfully delivered; absent until the first exchange |

### Example

```
luna-send -i luna://com.webos.service.nfc/getCardEmulationEvent '{"subscribe":true}'
```

```json
{ "returnValue": true, "subscribed": true }
{ "returnValue": true, "aidHex": "f04c756e654f53", "ok": true }
```
