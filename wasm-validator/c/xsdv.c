/*
 * xsdv.c - minimal XML Schema validator on top of libxml2, for WebAssembly.
 *
 * Design constraints (see ../README.md):
 *  - No callbacks into JS. Every function pointer handed to libxml2 is a C
 *    function in this file, so the wasm function table is fixed at link time.
 *  - No I/O. Schema documents come from an in-memory registry filled by the
 *    host through xv_register_file(); anything not in the registry fails to
 *    load. libxml2's default I/O callbacks are removed after init.
 *  - Instance documents: XML_PARSE_NONET, no NOENT/DTDLOAD/DTDATTR, and any
 *    DOCTYPE stops the parser (SAX internalSubset hook) and is reported as an
 *    error; the tree is additionally checked for DTD nodes after parsing.
 *  - Errors are collected into a static buffer as NUL-separated strings and
 *    are never written to stdout/stderr.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <malloc.h>

#include <libxml/parser.h>
#include <libxml/parserInternals.h>
#include <libxml/tree.h>
#include <libxml/xmlerror.h>
#include <libxml/xmlIO.h>
#include <libxml/xmlschemas.h>

#define EXPORT(name) __attribute__((export_name(name))) __attribute__((used))

/* ------------------------------------------------------------------ */
/* Error buffer                                                        */
/* ------------------------------------------------------------------ */

#define ERRBUF_SIZE (16 * 1024)
#define MAX_ERRORS 32
#define MAX_MSG 1024

static char err_buf[ERRBUF_SIZE];
static int err_len;   /* bytes used, including NUL separators */
static int err_count; /* messages stored */
static int err_dropped;

static void errors_reset(void) {
    err_len = 0;
    err_count = 0;
    err_dropped = 0;
}

static void errors_add(const char *msg) {
    size_t n;
    if (err_count >= MAX_ERRORS) { err_dropped++; return; }
    n = strlen(msg);
    if (n > MAX_MSG) n = MAX_MSG;
    if ((size_t) err_len + n + 1 > ERRBUF_SIZE) { err_dropped++; return; }
    memcpy(err_buf + err_len, msg, n);
    err_buf[err_len + n] = 0;
    err_len += (int) n + 1;
    err_count++;
}

static int keep_warnings;

/* Structured error handler used for every libxml2 context we create. */
static void on_error(void *user, const xmlError *e) {
    char line[MAX_MSG + 64];
    char msg[MAX_MSG];
    size_t n, i;
    (void) user;
    if (e == NULL) return;
    /* warnings do not fail validation; while compiling schemas they are kept
     * so that a failed compilation can be diagnosed */
    if (e->level == XML_ERR_WARNING && !keep_warnings) return;
    if (e->message != NULL) {
        n = strlen(e->message);
        if (n >= sizeof(msg)) n = sizeof(msg) - 1;
        memcpy(msg, e->message, n);
    } else {
        n = 0;
    }
    msg[n] = 0;
    /* trim trailing whitespace, flatten embedded newlines */
    while (n > 0 && (msg[n - 1] == '\n' || msg[n - 1] == ' ' || msg[n - 1] == '\r')) msg[--n] = 0;
    for (i = 0; i < n; i++) if (msg[i] == '\n' || msg[i] == '\r') msg[i] = ' ';
    if (e->line > 0 && e->file != NULL && keep_warnings)
        snprintf(line, sizeof(line), "%s:%d: %s", e->file, e->line, msg);
    else if (e->line > 0)
        snprintf(line, sizeof(line), "line %d: %s", e->line, msg);
    else
        snprintf(line, sizeof(line), "%s", msg);
    errors_add(line);
}

/* Global fallback: anything reported without a context-specific handler. */
static void on_generic_error(void *ctx, const char *fmt, ...) {
    (void) ctx; (void) fmt; /* swallowed: all our contexts have structured handlers */
}

/* ------------------------------------------------------------------ */
/* In-memory file registry                                             */
/* ------------------------------------------------------------------ */

#define MAX_FILES 32

typedef struct { char *name; char *data; size_t len; } reg_file;
static reg_file files[MAX_FILES];
static int nfiles;

static const reg_file *registry_find(const char *url) {
    int i;
    if (url == NULL) return NULL;
    for (i = 0; i < nfiles; i++)
        if (strcmp(files[i].name, url) == 0) return &files[i];
    return NULL;
}

/* Resource loader for schema parsing: registry only. */
static xmlParserErrors registry_loader(void *ctxt, const char *url, const char *publicId,
                                       xmlResourceType type, xmlParserInputFlags flags,
                                       xmlParserInput **out) {
    const reg_file *f = registry_find(url);
    (void) ctxt; (void) publicId; (void) type;
    *out = NULL;
    if (f == NULL) return XML_IO_ENOENT;
    *out = xmlNewInputFromMemory(f->name, f->data, f->len, flags | XML_INPUT_BUF_STATIC);
    return *out == NULL ? XML_ERR_NO_MEMORY : XML_ERR_OK;
}

/* Global input callbacks, also registry-only. Needed because libxml2
 * 2.15.4's xmlSchemaParseNewDoc() creates a nested schema parser context for
 * each imported/included document without copying the resource loader, so
 * <import>s inside imported schemas go through the global I/O callbacks. The
 * default (file) callbacks are removed in ensure_init(); these are the only
 * ones left. */
typedef struct { const reg_file *f; size_t pos; } reg_stream;

static int registry_match(const char *url) { return registry_find(url) != NULL; }

static void *registry_open(const char *url) {
    const reg_file *f = registry_find(url);
    reg_stream *s;
    if (f == NULL) return NULL;
    s = malloc(sizeof(*s));
    if (s == NULL) return NULL;
    s->f = f;
    s->pos = 0;
    return s;
}

static int registry_read(void *ctx, char *buf, int len) {
    reg_stream *s = ctx;
    size_t n = s->f->len - s->pos;
    if (len < 0) return -1;
    if (n > (size_t) len) n = (size_t) len;
    memcpy(buf, s->f->data + s->pos, n);
    s->pos += n;
    return (int) n;
}

static int registry_close(void *ctx) { free(ctx); return 0; }

/* Resource loader for instance documents: nothing may be loaded. */
static xmlParserErrors deny_loader(void *ctxt, const char *url, const char *publicId,
                                   xmlResourceType type, xmlParserInputFlags flags,
                                   xmlParserInput **out) {
    (void) ctxt; (void) url; (void) publicId; (void) type; (void) flags;
    *out = NULL;
    return XML_IO_EACCES;
}

/* ------------------------------------------------------------------ */
/* Init                                                                */
/* ------------------------------------------------------------------ */

static int initialized;

static void ensure_init(void) {
    if (initialized) return;
    xmlInitParser();
    /* Remove the default file-based input callbacks: after this, the only
     * way to obtain a document is the in-memory registry (or a resource
     * loader set on a context). */
    xmlCleanupInputCallbacks();
    xmlRegisterInputCallbacks(registry_match, registry_open, registry_read, registry_close);
    xmlSetGenericErrorFunc(NULL, on_generic_error);
    xmlSetStructuredErrorFunc(NULL, on_error);
    initialized = 1;
}

/* ------------------------------------------------------------------ */
/* Exports                                                             */
/* ------------------------------------------------------------------ */

EXPORT("xv_malloc") void *xv_malloc(size_t n) { return malloc(n); }
EXPORT("xv_free") void xv_free(void *p) { free(p); }

EXPORT("xv_errors_ptr") const char *xv_errors_ptr(void) { return err_buf; }
EXPORT("xv_errors_len") int xv_errors_len(void) { return err_len; }
EXPORT("xv_errors_count") int xv_errors_count(void) { return err_count; }
EXPORT("xv_errors_dropped") int xv_errors_dropped(void) { return err_dropped; }

/* Bytes currently allocated by malloc (for leak checks). */
EXPORT("xv_heap_used") int xv_heap_used(void) { return mallinfo().uordblks; }

/* Copies name and data. Returns 0 on success, -1 on error. */
EXPORT("xv_register_file")
int xv_register_file(const char *name, int name_len, const char *data, int data_len) {
    reg_file *f;
    int i;
    if (name_len <= 0 || data_len < 0) return -1;
    for (i = 0; i < nfiles; i++)
        if ((int) strlen(files[i].name) == name_len && memcmp(files[i].name, name, name_len) == 0)
            return -1; /* no replacement: schemas may already be compiled from it */
    if (nfiles >= MAX_FILES) return -1;
    f = &files[nfiles];
    f->name = malloc(name_len + 1);
    f->data = malloc(data_len > 0 ? data_len : 1);
    if (f->name == NULL || f->data == NULL) { free(f->name); free(f->data); return -1; }
    memcpy(f->name, name, name_len);
    f->name[name_len] = 0;
    memcpy(f->data, data, data_len);
    f->len = data_len;
    nfiles++;
    return 0;
}

#define MAX_KINDS 4
static xmlSchemaPtr schemas[MAX_KINDS];

/* Compile the schema set whose entry document is `entry` (a registered
 * file name) into slot `kind`. Returns 0 on success, -1 on failure
 * (errors in the error buffer). */
EXPORT("xv_compile")
int xv_compile(int kind, const char *entry, int entry_len) {
    char name[256];
    xmlSchemaParserCtxtPtr pctxt;
    xmlSchemaPtr schema;
    ensure_init();
    errors_reset();
    if (kind < 0 || kind >= MAX_KINDS || schemas[kind] != NULL) { errors_add("bad schema slot"); return -1; }
    if (entry_len <= 0 || entry_len >= (int) sizeof(name)) { errors_add("bad entry name"); return -1; }
    memcpy(name, entry, entry_len);
    name[entry_len] = 0;
    if (registry_find(name) == NULL) { errors_add("entry schema not registered"); return -1; }

    pctxt = xmlSchemaNewParserCtxt(name);
    if (pctxt == NULL) { errors_add("out of memory"); return -1; }
    xmlSchemaSetParserStructuredErrors(pctxt, on_error, NULL);
    xmlSchemaSetResourceLoader(pctxt, registry_loader, NULL);
    keep_warnings = 1;
    schema = xmlSchemaParse(pctxt);
    keep_warnings = 0;
    xmlSchemaFreeParserCtxt(pctxt);
    if (schema == NULL) {
        if (err_count == 0) errors_add("schema compilation failed");
        return -1;
    }
    schemas[kind] = schema;
    return 0;
}

/* SAX hook: called as soon as "<!DOCTYPE name ..." has been read, before any
 * internal subset is parsed. Stops the parser. */
static int saw_doctype;
static void reject_doctype(void *ctx, const xmlChar *name, const xmlChar *ExternalID,
                           const xmlChar *SystemID) {
    (void) name; (void) ExternalID; (void) SystemID;
    saw_doctype = 1;
    xmlStopParser((xmlParserCtxtPtr) ctx);
}

#define PARSE_OPTIONS (XML_PARSE_NONET | XML_PARSE_NO_XXE | XML_PARSE_NOERROR | \
                       XML_PARSE_NOWARNING | XML_PARSE_NOCDATA)

/* Returns 0 = valid, 1 = invalid (errors in buffer), -1 = internal error. */
EXPORT("xv_validate")
int xv_validate(int kind, const char *xml, int xml_len) {
    xmlParserCtxtPtr ctxt;
    xmlSAXHandler *sax;
    xmlDocPtr doc;
    xmlNodePtr n;
    xmlSchemaValidCtxtPtr vctxt;
    int rc;

    ensure_init();
    errors_reset();
    if (kind < 0 || kind >= MAX_KINDS || schemas[kind] == NULL) { errors_add("schema not compiled"); return -1; }
    if (xml_len <= 0) { errors_add("empty document"); return 1; }

    ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) { errors_add("out of memory"); return -1; }
    xmlCtxtSetErrorHandler(ctxt, on_error, NULL);
    xmlCtxtSetResourceLoader(ctxt, deny_loader, NULL);
    sax = (xmlSAXHandler *) xmlCtxtGetSaxHandler(ctxt);
    sax->internalSubset = reject_doctype;
    sax->externalSubset = NULL;
    saw_doctype = 0;

    /* The host passes UTF-8 (a decoded JS string), so force UTF-8 and ignore
     * any encoding in the XML declaration. */
    doc = xmlCtxtReadMemory(ctxt, xml, xml_len, NULL, "UTF-8", PARSE_OPTIONS);
    if (saw_doctype) {
        errors_add("DOCTYPE is not allowed");
        if (doc != NULL) xmlFreeDoc(doc);
        xmlFreeParserCtxt(ctxt);
        return 1;
    }
    if (doc == NULL || !ctxt->wellFormed) {
        if (err_count == 0) errors_add("document is not well-formed");
        if (doc != NULL) xmlFreeDoc(doc);
        xmlFreeParserCtxt(ctxt);
        return 1;
    }
    xmlFreeParserCtxt(ctxt);

    /* Belt and braces: no DTD of any kind in the tree. */
    if (doc->intSubset != NULL || doc->extSubset != NULL) {
        errors_add("DOCTYPE is not allowed");
        xmlFreeDoc(doc);
        return 1;
    }
    for (n = doc->children; n != NULL; n = n->next) {
        if (n->type == XML_DTD_NODE) {
            errors_add("DOCTYPE is not allowed");
            xmlFreeDoc(doc);
            return 1;
        }
    }

    vctxt = xmlSchemaNewValidCtxt(schemas[kind]);
    if (vctxt == NULL) { xmlFreeDoc(doc); errors_add("out of memory"); return -1; }
    xmlSchemaSetValidStructuredErrors(vctxt, on_error, NULL);
    rc = xmlSchemaValidateDoc(vctxt, doc);
    xmlSchemaFreeValidCtxt(vctxt);
    xmlFreeDoc(doc);

    if (rc == 0) { errors_reset(); return 0; }
    if (rc > 0) { if (err_count == 0) errors_add("document is not schema-valid"); return 1; }
    if (err_count == 0) errors_add("internal validation error");
    return -1;
}
