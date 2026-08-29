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

The full API reference, including parameters, reply schemas, subscription
behaviour, error texts and the ACG permission groups, lives in
[docs/API.md](docs/API.md). The short version:

| Method | Purpose |
|---|---|
| `getStatus` | Daemon/adapter state (subscribable) |
| `setEnabled` | Turn NFC on or off (persistent, stored by nfcd) |
| `getTagInfo` | The tag currently in the field, with decoded NDEF records, a raw Type 2 dump, and MIFARE Classic sectors (subscribable) |
| `writeTag` | Write a single-record NDEF message: URI, text, vCard, Wi-Fi credentials or Bluetooth pairing |
| `lockTag` | Permanently write-protect a Type 2 tag |
| `cloneTag` | Replay a raw Type 2 dump onto another tag byte for byte |
| `readPassport` | Read an ICAO 9303 eMRTD chip (passport/eID) via BAC, optionally with the DG2 photo |
| `readPassportPACE` | The same read via PACE, for documents that only print a CAN |
| `addCardEmulationProfile` | Register a fixed-response HCE profile under an AID |
| `removeCardEmulationProfile` | Unregister one HCE profile |
| `clearCardEmulation` | Unregister all HCE profiles |
| `getCardEmulationEvent` | Last reader-confirmed HCE exchange (subscribable) |

For example:

    luna-send -i -n 2 luna://com.webos.service.nfc/getStatus '{"subscribe":true}'
    luna-send -n 1 luna://com.webos.service.nfc/writeTag \
        '{"type":"uri","uri":"https://www.webos-ports.org"}'

What is not here
----------------
Contactless payments. The card emulation here is a deliberately simple
fixed-response profile per AID (a personal badge identifier, not a card):
payments additionally need tokenised card credentials issued through Visa VTS
or Mastercard MDES and an EMVCo certified kernel, which are commercial
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
