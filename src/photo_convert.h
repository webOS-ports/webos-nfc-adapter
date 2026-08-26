/* @@@LICENSE
*
* Copyright (c) 2026 Herman van Hazendonk <github.com@herrie.org>
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* LICENSE@@@ */

#ifndef PHOTO_CONVERT_H_
#define PHOTO_CONVERT_H_

#include <glib.h>

/*
 * DG2 facial photos are near-universally JPEG2000, which this platform's
 * Qt/QML stack cannot decode (no image plugin, no on-device conversion
 * tool). Re-encodes to uncompressed BMP instead - QML can always display
 * that, no plugin needed. Returns NULL on any decode failure (corrupt or
 * unsupported JP2 structure); never crashes on bad input.
 */
GByteArray *photo_jp2_to_bmp(const guint8 *jp2, gsize jp2_len);

#endif
