/* Minimal stand-in for pbnjson_c, only for host side syntax checking. */
#ifndef PBNJSON_STUB_H
#define PBNJSON_STUB_H
#include <stdbool.h>
#include <stddef.h>

typedef struct jvalue *jvalue_ref;
typedef struct jschema *jschema_ref;
typedef struct { const char *m_str; size_t m_len; } raw_buffer;
typedef struct { int dummy; } JSchemaInfo;
typedef enum { DOMOPT_NOOPT = 0 } JDOMOptimization;

extern jvalue_ref jobject_create(void);
extern jvalue_ref jarray_create(void *opts);
extern bool jobject_put(jvalue_ref obj, jvalue_ref key, jvalue_ref val);
extern bool jarray_append(jvalue_ref arr, jvalue_ref val);
extern jvalue_ref jstring_create(const char *str);
extern jvalue_ref jnumber_create_i32(int num);
extern jvalue_ref jboolean_create(bool val);
extern jvalue_ref jnull(void);
extern void j_release(jvalue_ref *val);
extern jvalue_ref jvalue_duplicate(jvalue_ref val);
extern bool jobject_get_exists(jvalue_ref obj, raw_buffer key, jvalue_ref *val);
extern bool jis_null(jvalue_ref val);
extern bool jis_string(jvalue_ref val);
extern bool jis_boolean(jvalue_ref val);
extern bool jis_number(jvalue_ref val);
extern int jboolean_get(jvalue_ref val, bool *out);   /* JResult: 0 == OK */
extern int jnumber_get_i32(jvalue_ref val, int *out);   /* JResult: 0 == OK */
extern raw_buffer jstring_get_fast(jvalue_ref val);
extern const char *jvalue_tostring(jvalue_ref val, jschema_ref schema);
extern jschema_ref jschema_parse(raw_buffer input, JDOMOptimization opt, void *err);
extern void jschema_release(jschema_ref *schema);
extern void jschema_info_init(JSchemaInfo *info, jschema_ref schema, void *a, void *b);
extern jvalue_ref jdom_parse(raw_buffer input, JDOMOptimization opt, JSchemaInfo *info);
extern raw_buffer j_cstr_to_buffer(const char *str);
extern jvalue_ref j_cstr_to_jval(const char *str);
#define J_CSTR_TO_JVAL(s) j_cstr_to_jval(s)
#define J_CSTR_TO_BUF(s) j_cstr_to_buffer(s)
#endif
