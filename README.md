webos-nfc-adapter
=================

Summary
-------
Bridges the nfcd D-Bus API onto the luna-service2 bus as `com.webos.service.nfc`.

Description
-----------
On Halium devices the NFC controller is reached through the Android NFC HAL
rather than the in-kernel Linux NFC subsystem, so LuneOS uses
[nfcd](https://github.com/sailfishos/nfcd) together with
[nfcd-binder-plugin](https://github.com/mer-hybris/nfcd-binder-plugin), the same
stack Sailfish OS, Ubuntu Touch and Droidian use. nfcd speaks D-Bus; webOS apps
and the shell speak luna-service2. This daemon sits between the two.

    Android NFC HAL  ──binder──▶  nfcd  ──D-Bus──▶  webos-nfc-adapter  ──LS2──▶  apps

It watches both nfcd bus names, so nfcd restarting, or not being installed at
all, is a normal state rather than an error: the service simply reports
`available: false` and re-attaches when nfcd comes back.

Requires nfcd >= 1.2.0 for the `GetAll4` calls.

Luna service API
----------------

### com.webos.service.nfc/getStatus

Subscribable. Reports the state of the daemon and the adapter.

    luna-send -i -n 2 luna://com.webos.service.nfc/getStatus '{"subscribe":true}'

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

`available` is true once nfcd is running and has published an adapter.
`enabled` is the persistent user setting, `powered` is whether the controller
is actually up, and `present` is true while something is in the field.

`mode` and `supportedModes` are the nfcd mode bitmask: `0x01` P2P initiator,
`0x02` reader/writer, `0x04` P2P target, `0x08` card emulation. `techs` is
`0x01` NFC-A, `0x02` NFC-B, `0x04` NFC-F.

### com.webos.service.nfc/setEnabled

Turns NFC on or off. The setting is persistent, nfcd stores it.

    luna-send -n 1 luna://com.webos.service.nfc/setEnabled '{"enabled":true}'

### com.webos.service.nfc/getTagInfo

Subscribable. Reports the tag currently in the field. A subscriber gets one
update when a tag arrives (with `present` true but no `tag` yet), a second once
the tag and its NDEF records have been read, and a third when it is removed.

    luna-send -i -n 5 luna://com.webos.service.nfc/getTagInfo '{"subscribe":true}'

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
        "type": 2,
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
        ]
    }
}
```

`NFCID1` in `pollParameters` is the tag UID, which is what access badge style
uses care about.

Records carry their raw fields plus, where we understand the type, a decoded
form: `kind` `uri` adds `uri`, `kind` `text` adds `text` and `language`, `kind`
`media` adds `mediaType`, and `kind` `smartposter` adds a nested `records`
array.

### com.webos.service.nfc/writeTag

Writes a single record NDEF message to the tag currently in the field.

    luna-send -n 1 luna://com.webos.service.nfc/writeTag \
        '{"type":"uri","uri":"https://www.webos-ports.org"}'

    luna-send -n 1 luna://com.webos.service.nfc/writeTag \
        '{"type":"text","text":"hello","language":"en"}'

Only Type 2 tags (NTAG21x, MIFARE Ultralight and friends, which is what blank
tags almost always are) can be written: writing goes through nfcd's
`org.sailfishos.nfc.TagType2` interface. Anything else returns an error rather
than pretending to work. The tag is acquired for exclusive access for the
duration of the write and released afterwards.

What is not here
----------------
Card emulation. nfcd supports it, and the LuneOS side could grow a
`registerHostApp` style call on top of `org.sailfishos.nfc.LocalHostApp`, but
note that host card emulation on its own does not get you contactless payments:
those additionally need tokenised card credentials issued through Visa VTS or
Mastercard MDES and an EMVCo certified kernel, which are commercial
arrangements rather than missing code.

How to Build on Linux
=====================

## Dependencies

* cmake (version required by openwebos/cmake-modules-webos)
* gcc
* glib-2.0, gio-2.0, gio-unix-2.0, gobject-2.0
* gdbus-codegen (from glib-2.0, used at configure time)
* openwebos/luna-service2
* openwebos/pbnjson_c
* pkg-config

## Building

    $ mkdir BUILD
    $ cd BUILD
    $ cmake ..
    $ make
    $ sudo make install

The directory under which the files are installed defaults to
`/usr/local/webos`. Supply `WEBOS_INSTALL_ROOT` to `cmake` to change that.

## Tests

The NDEF encoders produce the bytes that end up written to a tag, so they have
a host side check that needs nothing but glib:

    $ make -C test check

# Copyright and License Information

Unless otherwise specified, all content, including all source code files and
documentation files in this repository are:

Copyright (c) 2026 Herman van Hazendonk <github.com@herrie.org>

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

SPDX-License-Identifier: Apache-2.0
