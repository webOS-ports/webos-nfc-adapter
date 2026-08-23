#include <stdio.h>
#include <string.h>
#include "ndef.h"

/* ndef.c pulls in pbnjson for the JSON side; the encoders under test don't
 * touch it, so satisfy the linker with stubs. */
jvalue_ref jobject_create(void){return 0;} jvalue_ref jarray_create(void*o){(void)o;return 0;}
bool jobject_put(jvalue_ref a,jvalue_ref b,jvalue_ref c){(void)a;(void)b;(void)c;return 1;}
bool jarray_append(jvalue_ref a,jvalue_ref b){(void)a;(void)b;return 1;}
jvalue_ref jstring_create(const char*s){(void)s;return 0;}
jvalue_ref jnumber_create_i32(int i){(void)i;return 0;}
jvalue_ref jboolean_create(bool b){(void)b;return 0;}
void j_release(jvalue_ref*v){(void)v;}
jvalue_ref j_cstr_to_jval(const char*s){(void)s;return 0;}

static int fails = 0;
static void check_hex(const char *what, GByteArray *got, const char *expect)
{
    GString *s = g_string_new(NULL);
    for (guint i = 0; i < got->len; i++) g_string_append_printf(s, "%02x", got->data[i]);
    if (strcmp(s->str, expect) == 0) { printf("  ok   %-28s %s\n", what, s->str); }
    else { printf("  FAIL %-28s\n       got      %s\n       expected %s\n", what, s->str, expect); fails++; }
    g_string_free(s, TRUE);
}

int main(void)
{
    GByteArray *m, *t;

    /* URI record, "https://www." abbreviated to prefix code 0x02.
       header d1 = MB|ME|SR|TNF1, type len 01, payload len 0c, 'U'=55,
       code 02, then "example.com" (11 bytes) */
    m = ndef_build_uri_message("https://www.example.com");
    check_hex("uri https://www.", m, "d101" "0c" "55" "02" "6578616d706c652e636f6d");
    g_byte_array_free(m, TRUE);

    /* No matching abbreviation -> code 0x00 and the full URI */
    m = ndef_build_uri_message("foo:bar");
    check_hex("uri no prefix", m, "d101" "08" "55" "00" "666f6f3a626172");
    g_byte_array_free(m, TRUE);

    /* Longest prefix must win: "http://www." (0x01) not "http://" (0x03) */
    m = ndef_build_uri_message("http://www.a.b");
    check_hex("uri longest prefix", m, "d101" "04" "55" "01" "612e62");
    g_byte_array_free(m, TRUE);

    /* Text record: status byte 02 (utf8, lang len 2), "en", "hi" */
    m = ndef_build_text_message("hi", "en");
    check_hex("text en", m, "d101" "05" "54" "02" "656e" "6869");

    /* TLV wrap: 03 <len> <message> fe */
    t = ndef_wrap_type2_tlv(m);
    check_hex("type2 tlv", t, "03" "09" "d101055402656e6869" "fe");
    g_byte_array_free(t, TRUE);
    g_byte_array_free(m, TRUE);

    printf("%s\n", fails ? "FAILURES" : "all passed");
    return fails != 0;
}
