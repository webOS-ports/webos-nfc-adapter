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

#include "photo_convert.h"

#include <openjpeg.h>
#include <string.h>

static const guint8 jp2_box_magic[] = { 0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20,
                                        0x0D, 0x0A, 0x87, 0x0A };

/* opj_stream_t reads from a fixed memory buffer - openjpeg has no built-in
 * memory stream, every embedder hand-rolls this same read/skip/seek trio. */
typedef struct {
	const guint8 *data;
	OPJ_SIZE_T len;
	OPJ_SIZE_T pos;
} MemStream;

static OPJ_SIZE_T mem_read(void *dst, OPJ_SIZE_T n, void *user_data)
{
	MemStream *s = user_data;
	OPJ_SIZE_T avail = s->len - s->pos;
	OPJ_SIZE_T take = (n < avail) ? n : avail;

	if (take == 0)
		return (OPJ_SIZE_T) -1;	/* openjpeg's EOF convention */
	memcpy(dst, s->data + s->pos, take);
	s->pos += take;
	return take;
}

static OPJ_OFF_T mem_skip(OPJ_OFF_T n, void *user_data)
{
	MemStream *s = user_data;
	OPJ_SIZE_T avail = s->len - s->pos;
	OPJ_SIZE_T take;

	if (n < 0)
		return -1;
	take = ((OPJ_SIZE_T) n < avail) ? (OPJ_SIZE_T) n : avail;
	s->pos += take;
	return (OPJ_OFF_T) take;
}

static OPJ_BOOL mem_seek(OPJ_OFF_T n, void *user_data)
{
	MemStream *s = user_data;

	if (n < 0 || (OPJ_SIZE_T) n > s->len)
		return OPJ_FALSE;
	s->pos = (OPJ_SIZE_T) n;
	return OPJ_TRUE;
}

/* Silences openjpeg's default stderr logging - failures are reported via
 * the NULL return instead. */
static void quiet_log(const char *msg, void *user_data)
{
	(void) msg;
	(void) user_data;
}

static guint8 clamp_sample(OPJ_INT32 v, OPJ_UINT32 prec, OPJ_UINT32 sgnd)
{
	OPJ_INT32 max = (1 << prec) - 1;

	if (sgnd)
		v += (1 << (prec - 1));
	if (v < 0)
		v = 0;
	if (v > max)
		v = max;
	/* Scale prec-bit samples to 8-bit - DG2 photos are typically 8-bit
	 * already, but don't assume it. */
	return (guint8)(prec >= 8 ? (v >> (prec - 8)) : (v << (8 - prec)));
}

static void bmp_append_u32(GByteArray *out, guint32 v)
{
	guint8 b[4] = { (guint8) v, (guint8)(v >> 8), (guint8)(v >> 16), (guint8)(v >> 24) };
	g_byte_array_append(out, b, 4);
}

static void bmp_append_u16(GByteArray *out, guint16 v)
{
	guint8 b[2] = { (guint8) v, (guint8)(v >> 8) };
	g_byte_array_append(out, b, 2);
}

/* Standard uncompressed 24bpp BMP: BITMAPFILEHEADER + BITMAPINFOHEADER,
 * bottom-up row order, BGR sample order, rows padded to 4 bytes. */
static GByteArray *encode_bmp(const guint8 *rgb, guint32 width, guint32 height)
{
	guint32 row_bytes = width * 3;
	guint32 row_padded = (row_bytes + 3) & ~3u;
	guint32 pixel_data_len = row_padded * height;
	guint32 file_len = 14 + 40 + pixel_data_len;
	GByteArray *bmp = g_byte_array_new();

	g_byte_array_append(bmp, (const guint8 *) "BM", 2);
	bmp_append_u32(bmp, file_len);
	bmp_append_u32(bmp, 0);		/* reserved */
	bmp_append_u32(bmp, 14 + 40);		/* pixel data offset */

	bmp_append_u32(bmp, 40);		/* BITMAPINFOHEADER size */
	bmp_append_u32(bmp, width);
	bmp_append_u32(bmp, height);		/* positive => bottom-up */
	bmp_append_u16(bmp, 1);		/* planes */
	bmp_append_u16(bmp, 24);		/* bpp */
	bmp_append_u32(bmp, 0);		/* BI_RGB, no compression */
	bmp_append_u32(bmp, pixel_data_len);
	bmp_append_u32(bmp, 0);		/* x pixels/meter */
	bmp_append_u32(bmp, 0);		/* y pixels/meter */
	bmp_append_u32(bmp, 0);		/* colors used */
	bmp_append_u32(bmp, 0);		/* important colors */

	for (gint32 y = (gint32) height - 1; y >= 0; y--) {
		guint32 pad = row_padded - row_bytes;
		const guint8 *row = rgb + (gsize) y * row_bytes;

		for (guint32 x = 0; x < width; x++) {
			guint8 bgr[3] = { row[x * 3 + 2], row[x * 3 + 1], row[x * 3 + 0] };
			g_byte_array_append(bmp, bgr, 3);
		}
		if (pad) {
			guint8 zero[3] = { 0, 0, 0 };
			g_byte_array_append(bmp, zero, pad);
		}
	}

	return bmp;
}

GByteArray *photo_jp2_to_bmp(const guint8 *jp2, gsize jp2_len)
{
	gboolean is_jp2_box = jp2_len >= sizeof(jp2_box_magic) &&
	                      memcmp(jp2, jp2_box_magic, sizeof(jp2_box_magic)) == 0;
	MemStream mem = { jp2, (OPJ_SIZE_T) jp2_len, 0 };
	opj_stream_t *stream = NULL;
	opj_codec_t *codec = NULL;
	opj_dparameters_t params;
	opj_image_t *image = NULL;
	GByteArray *bmp = NULL;
	guint8 *rgb = NULL;

	stream = opj_stream_default_create(OPJ_TRUE);
	if (!stream)
		return NULL;
	opj_stream_set_read_function(stream, mem_read);
	opj_stream_set_skip_function(stream, mem_skip);
	opj_stream_set_seek_function(stream, mem_seek);
	opj_stream_set_user_data(stream, &mem, NULL);
	opj_stream_set_user_data_length(stream, mem.len);

	codec = opj_create_decompress(is_jp2_box ? OPJ_CODEC_JP2 : OPJ_CODEC_J2K);
	if (!codec)
		goto out;
	opj_set_info_handler(codec, quiet_log, NULL);
	opj_set_warning_handler(codec, quiet_log, NULL);
	opj_set_error_handler(codec, quiet_log, NULL);

	opj_set_default_decoder_parameters(&params);
	if (!opj_setup_decoder(codec, &params))
		goto out;

	if (!opj_read_header(stream, codec, &image))
		goto out;
	if (!opj_decode(codec, stream, image))
		goto out;

	if (image->numcomps < 1 || !image->comps[0].data)
		goto out;

	{
		guint32 width = image->comps[0].w;
		guint32 height = image->comps[0].h;
		gboolean rgb_ok = TRUE;

		/* DG2 photos are 4:4:4 (no chroma subsampling) - reject
		 * anything else rather than guess at resampling. */
		for (guint32 c = 0; c < image->numcomps && c < 3; c++) {
			if (image->comps[c].w != width || image->comps[c].h != height ||
			    image->comps[c].dx != 1 || image->comps[c].dy != 1 ||
			    !image->comps[c].data) {
				rgb_ok = FALSE;
				break;
			}
		}
		if (!rgb_ok || width == 0 || height == 0 ||
		    (guint64) width * height > 16 * 1024 * 1024)
			goto out;

		rgb = g_malloc((gsize) width * height * 3);
		for (guint32 i = 0; i < width * height; i++) {
			guint32 prec0 = image->comps[0].prec;
			guint8 r = clamp_sample(image->comps[0].data[i], prec0,
			                        image->comps[0].sgnd);
			guint8 g, b;

			if (image->numcomps >= 3) {
				g = clamp_sample(image->comps[1].data[i], image->comps[1].prec,
				                 image->comps[1].sgnd);
				b = clamp_sample(image->comps[2].data[i], image->comps[2].prec,
				                 image->comps[2].sgnd);
			} else {
				g = r;
				b = r;
			}
			rgb[i * 3 + 0] = r;
			rgb[i * 3 + 1] = g;
			rgb[i * 3 + 2] = b;
		}

		bmp = encode_bmp(rgb, width, height);
	}

out:
	g_free(rgb);
	if (image)
		opj_image_destroy(image);
	if (codec)
		opj_destroy_codec(codec);
	if (stream)
		opj_stream_destroy(stream);
	return bmp;
}
