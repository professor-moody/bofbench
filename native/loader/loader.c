#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#define MACHINE_AMD64 0x8664
#define SYM_UNDEFINED 0
#define REL_AMD64_ABSOLUTE 0x0000
#define REL_AMD64_ADDR64 0x0001
#define REL_AMD64_ADDR32 0x0002
#define REL_AMD64_ADDR32NB 0x0003
#define REL_AMD64_REL32 0x0004
#define REL_AMD64_REL32_1 0x0005
#define REL_AMD64_REL32_2 0x0006
#define REL_AMD64_REL32_3 0x0007
#define REL_AMD64_REL32_4 0x0008
#define REL_AMD64_REL32_5 0x0009

#pragma pack(push, 1)
typedef struct {
    uint16_t machine;
    uint16_t number_of_sections;
    uint32_t timestamp;
    uint32_t pointer_to_symbol_table;
    uint32_t number_of_symbols;
    uint16_t size_of_optional_header;
    uint16_t characteristics;
} coff_file_header;

typedef struct {
    uint8_t name[8];
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t size_of_raw_data;
    uint32_t pointer_to_raw_data;
    uint32_t pointer_to_relocations;
    uint32_t pointer_to_line_numbers;
    uint16_t number_of_relocations;
    uint16_t number_of_line_numbers;
    uint32_t characteristics;
} coff_section_header;

typedef struct {
    union {
        uint8_t short_name[8];
        struct {
            uint32_t zeroes;
            uint32_t offset;
        } long_name;
    } name;
    uint32_t value;
    int16_t section_number;
    uint16_t type;
    uint8_t storage_class;
    uint8_t number_of_aux_symbols;
} coff_symbol;

typedef struct {
    uint32_t virtual_address;
    uint32_t symbol_table_index;
    uint16_t type;
} coff_relocation;
#pragma pack(pop)

typedef struct {
    char *buffer;
    int length;
    int offset;
} datap;

typedef struct {
    char *name;
    uintptr_t value;
    uintptr_t target;
} resolved_symbol;

static char g_output[128][4096];
static int g_output_count = 0;
static char g_error[128][4096];
static int g_error_count = 0;
static uint8_t *g_stub_cursor = NULL;
static uint8_t *g_stub_end = NULL;

static void add_line(char lines[128][4096], int *count, const char *fmt, ...) {
    if (*count >= 128) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(lines[*count], sizeof(lines[*count]), fmt, ap);
    va_end(ap);
    (*count)++;
}

static void add_output(const char *fmt, ...) {
    if (g_output_count >= 128) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_output[g_output_count], sizeof(g_output[g_output_count]), fmt, ap);
    va_end(ap);
    g_output_count++;
}

void BeaconDataParse(datap *parser, char *buffer, int size) {
    if (!parser) return;
    parser->buffer = buffer;
    parser->length = size;
    parser->offset = 0;
}

int BeaconDataInt(datap *parser) {
    int out = 0;
    if (!parser || parser->offset + 4 > parser->length) return 0;
    memcpy(&out, parser->buffer + parser->offset, 4);
    parser->offset += 4;
    return out;
}

short BeaconDataShort(datap *parser) {
    short out = 0;
    if (!parser || parser->offset + 2 > parser->length) return 0;
    memcpy(&out, parser->buffer + parser->offset, 2);
    parser->offset += 2;
    return out;
}

int BeaconDataLength(datap *parser) {
    if (!parser) return 0;
    return parser->length - parser->offset;
}

char *BeaconDataExtract(datap *parser, int *size) {
    int len = 0;
    char *out = NULL;
    if (size) *size = 0;
    if (!parser || parser->offset + 4 > parser->length) return NULL;
    memcpy(&len, parser->buffer + parser->offset, 4);
    parser->offset += 4;
    if (len < 0 || parser->offset + len > parser->length) return NULL;
    out = parser->buffer + parser->offset;
    parser->offset += len;
    if (size) *size = len;
    return out;
}

void BeaconOutput(int type, char *data, int len) {
    (void)type;
    if (!data || len <= 0) {
        add_output("");
        return;
    }
    char tmp[4096];
    int n = len < (int)sizeof(tmp) - 1 ? len : (int)sizeof(tmp) - 1;
    memcpy(tmp, data, n);
    tmp[n] = 0;
    add_output("%s", tmp);
}

void BeaconPrintf(int type, const char *fmt, ...) {
    (void)type;
    if (!fmt) return;
    char tmp[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    add_output("%s", tmp);
}

static void *read_file(const char *path, size_t *out_size) {
    FILE *f = fopen(path, "rb");
    void *buf;
    long size;
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size <= 0) {
        fclose(f);
        return NULL;
    }
    buf = calloc(1, (size_t)size);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    if (fread(buf, 1, (size_t)size, f) != (size_t)size) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *out_size = (size_t)size;
    return buf;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static unsigned char *decode_hex(const char *hex, int *out_len) {
    size_t len = hex ? strlen(hex) : 0;
    unsigned char *out;
    size_t i;
    if (len % 2 != 0) return NULL;
    out = (unsigned char *)calloc(1, len / 2 + 1);
    if (!out) return NULL;
    for (i = 0; i < len; i += 2) {
        int hi = hexval(hex[i]);
        int lo = hexval(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            free(out);
            return NULL;
        }
        out[i / 2] = (unsigned char)((hi << 4) | lo);
    }
    *out_len = (int)(len / 2);
    return out;
}

static char *symbol_name(coff_symbol *sym, char *string_table, size_t string_table_size, char *buf, size_t buflen) {
    if (sym->name.long_name.zeroes == 0) {
        uint32_t off = sym->name.long_name.offset;
        if (off < string_table_size) return string_table + off;
        snprintf(buf, buflen, "<bad-string-%u>", off);
        return buf;
    }
    memcpy(buf, sym->name.short_name, 8);
    buf[8] = 0;
    return buf;
}

static const char *relocation_type_name(uint16_t type) {
    switch (type) {
    case REL_AMD64_ABSOLUTE: return "ABSOLUTE";
    case REL_AMD64_ADDR64: return "ADDR64";
    case REL_AMD64_ADDR32: return "ADDR32";
    case REL_AMD64_ADDR32NB: return "ADDR32NB";
    case REL_AMD64_REL32: return "REL32";
    case REL_AMD64_REL32_1: return "REL32_1";
    case REL_AMD64_REL32_2: return "REL32_2";
    case REL_AMD64_REL32_3: return "REL32_3";
    case REL_AMD64_REL32_4: return "REL32_4";
    case REL_AMD64_REL32_5: return "REL32_5";
    default: return "UNKNOWN";
    }
}

static char *relocation_symbol_name(
    coff_relocation *rel,
    coff_symbol *symbols,
    uint32_t symbol_count,
    char *string_table,
    size_t string_table_size,
    char *buf,
    size_t buflen
) {
    if (rel->symbol_table_index >= symbol_count) {
        snprintf(buf, buflen, "<bad-symbol-index-%u>", rel->symbol_table_index);
        return buf;
    }
    return symbol_name(&symbols[rel->symbol_table_index], string_table, string_table_size, buf, buflen);
}

static char *strip_import_prefix(char *name) {
    if (strncmp(name, "__imp_", 6) == 0) return name + 6;
    if (strncmp(name, "__imp__", 7) == 0) return name + 7;
    return name;
}

static const char *normalized_import_name(const char *name, char *buf, size_t buflen) {
    snprintf(buf, buflen, "%s", name);
    return strip_import_prefix(buf);
}

static HMODULE load_symbol_library(const char *library) {
    char dll[320];
    snprintf(dll, sizeof(dll), "%s.dll", library);
    return LoadLibraryA(dll);
}

static int is_import_pointer_symbol(const char *name) {
    return strncmp(name, "__imp_", 6) == 0 || strncmp(name, "__imp__", 7) == 0;
}

static uintptr_t alloc_near_data_ptr(uintptr_t target) {
    uint8_t *slot;
    if (!g_stub_cursor || g_stub_cursor + 16 > g_stub_end) return 0;
    slot = g_stub_cursor;
    memset(slot, 0, 16);
    memcpy(slot, &target, sizeof(target));
    g_stub_cursor += 16;
    return (uintptr_t)slot;
}

static uintptr_t alloc_near_jump_stub(uintptr_t target) {
    uint8_t *stub;
    if (!g_stub_cursor || g_stub_cursor + 16 > g_stub_end) return 0;
    stub = g_stub_cursor;
    memset(stub, 0x90, 16);
    stub[0] = 0x48;
    stub[1] = 0xB8;
    memcpy(stub + 2, &target, sizeof(target));
    stub[10] = 0xFF;
    stub[11] = 0xE0;
    g_stub_cursor += 16;
    return (uintptr_t)stub;
}

static uintptr_t cache_external_value(const char *name, uintptr_t target, resolved_symbol *resolved, int *resolved_count) {
    uintptr_t value;
    if (!target) return 0;
    value = is_import_pointer_symbol(name) ? alloc_near_data_ptr(target) : alloc_near_jump_stub(target);
    if (!value) {
        add_line(g_error, &g_error_count, "external stub area exhausted while resolving %s", name);
        return 0;
    }
    if (*resolved_count < 512) {
        resolved[*resolved_count].name = _strdup(name);
        resolved[*resolved_count].target = target;
        resolved[*resolved_count].value = value;
        (*resolved_count)++;
    }
    return value;
}

static uintptr_t resolve_winapi_target(const char *name) {
    const char *libs[] = {"kernel32", "advapi32", "user32", "netapi32", "wtsapi32", "iphlpapi", "ws2_32", "secur32", "ole32", "shell32", "ntdll", "msvcrt"};
    char tmp[256];
    char *func;
    size_t i;
    snprintf(tmp, sizeof(tmp), "%s", name);
    func = strip_import_prefix(tmp);
    char *dollar = strchr(func, '$');
    if (dollar) {
        *dollar = 0;
        HMODULE mod = load_symbol_library(func);
        if (!mod) return 0;
        return (uintptr_t)GetProcAddress(mod, dollar + 1);
    }
    for (i = 0; i < sizeof(libs) / sizeof(libs[0]); i++) {
        HMODULE mod = load_symbol_library(libs[i]);
        FARPROC p;
        if (!mod) continue;
        p = GetProcAddress(mod, func);
        if (p) return (uintptr_t)p;
    }
    return 0;
}

static uintptr_t resolve_external(const char *name, resolved_symbol *resolved, int *resolved_count) {
    int i;
    uintptr_t target = 0;
    char normalized_buf[256];
    const char *normalized = normalized_import_name(name, normalized_buf, sizeof(normalized_buf));
    for (i = 0; i < *resolved_count; i++) {
        if (strcmp(resolved[i].name, name) == 0) return resolved[i].value;
    }
    if (strcmp(normalized, "BeaconDataParse") == 0) target = (uintptr_t)BeaconDataParse;
    else if (strcmp(normalized, "BeaconDataInt") == 0) target = (uintptr_t)BeaconDataInt;
    else if (strcmp(normalized, "BeaconDataShort") == 0) target = (uintptr_t)BeaconDataShort;
    else if (strcmp(normalized, "BeaconDataLength") == 0) target = (uintptr_t)BeaconDataLength;
    else if (strcmp(normalized, "BeaconDataExtract") == 0) target = (uintptr_t)BeaconDataExtract;
    else if (strcmp(normalized, "BeaconPrintf") == 0) target = (uintptr_t)BeaconPrintf;
    else if (strcmp(normalized, "BeaconOutput") == 0) target = (uintptr_t)BeaconOutput;
    else target = resolve_winapi_target(name);
    return cache_external_value(name, target, resolved, resolved_count);
}

static uintptr_t symbol_address(
    uint32_t index,
    coff_symbol *symbols,
    uint32_t symbol_count,
    char *string_table,
    size_t string_table_size,
    uint8_t **section_bases,
    int section_count,
    resolved_symbol *resolved,
    int *resolved_count
) {
    char name_buf[64];
    char *name;
    coff_symbol *sym;
    if (index >= symbol_count) return 0;
    sym = &symbols[index];
    name = symbol_name(sym, string_table, string_table_size, name_buf, sizeof(name_buf));
    if (sym->section_number > 0 && sym->section_number <= section_count) {
        return (uintptr_t)(section_bases[sym->section_number - 1] + sym->value);
    }
    if (sym->section_number == SYM_UNDEFINED) {
        return resolve_external(name, resolved, resolved_count);
    }
    return 0;
}

static int apply_relocations(
    uint8_t *image_base,
    coff_section_header *sections,
    int section_count,
    coff_symbol *symbols,
    uint32_t symbol_count,
    char *string_table,
    size_t string_table_size,
    uint8_t **section_bases,
    uint8_t *file_base,
    size_t file_size,
    resolved_symbol *resolved,
    int *resolved_count
) {
    int si, ri;
    for (si = 0; si < section_count; si++) {
        coff_section_header *sec = &sections[si];
        coff_relocation *rels = (coff_relocation *)(file_base + sec->pointer_to_relocations);
        size_t reloc_bytes = (size_t)sec->number_of_relocations * sizeof(coff_relocation);
        if (sec->number_of_relocations && ((size_t)sec->pointer_to_relocations > file_size || (size_t)sec->pointer_to_relocations + reloc_bytes > file_size)) {
            add_line(g_error, &g_error_count, "relocation table for section %.*s is outside object bounds", 8, sec->name);
            return 0;
        }
        for (ri = 0; ri < sec->number_of_relocations; ri++) {
            char sym_name_buf[128];
            coff_relocation *rel = &rels[ri];
            char *sym_name = relocation_symbol_name(rel, symbols, symbol_count, string_table, string_table_size, sym_name_buf, sizeof(sym_name_buf));
            uint8_t *where = section_bases[si] + rel->virtual_address;
            uintptr_t target = symbol_address(rel->symbol_table_index, symbols, symbol_count, string_table, string_table_size, section_bases, section_count, resolved, resolved_count);
            if (!target && rel->type != REL_AMD64_ABSOLUTE) {
                add_line(
                    g_error,
                    &g_error_count,
                    "unresolved symbol %s (index %u, relocation %s/0x%04x, section %.*s+0x%x)",
                    sym_name,
                    rel->symbol_table_index,
                    relocation_type_name(rel->type),
                    rel->type,
                    8,
                    sec->name,
                    rel->virtual_address
                );
                return 0;
            }
            switch (rel->type) {
            case REL_AMD64_ABSOLUTE:
                break;
            case REL_AMD64_ADDR64:
                *(uint64_t *)where = (uint64_t)(target + *(uint64_t *)where);
                break;
            case REL_AMD64_ADDR32:
                *(uint32_t *)where = (uint32_t)(target + *(uint32_t *)where);
                break;
            case REL_AMD64_ADDR32NB:
                *(uint32_t *)where = (uint32_t)(target - (uintptr_t)image_base + *(uint32_t *)where);
                break;
            case REL_AMD64_REL32:
            case REL_AMD64_REL32_1:
            case REL_AMD64_REL32_2:
            case REL_AMD64_REL32_3:
            case REL_AMD64_REL32_4:
            case REL_AMD64_REL32_5: {
                int adjust = 4 + (rel->type - REL_AMD64_REL32);
                int64_t disp = (int64_t)target + *(int32_t *)where - ((int64_t)(uintptr_t)where + adjust);
                *(int32_t *)where = (int32_t)disp;
                break;
            }
            default:
                add_line(
                    g_error,
                    &g_error_count,
                    "unsupported AMD64 relocation %s/0x%04x for symbol %s in section %.*s+0x%x",
                    relocation_type_name(rel->type),
                    rel->type,
                    sym_name,
                    8,
                    sec->name,
                    rel->virtual_address
                );
                return 0;
            }
        }
    }
    return 1;
}

static void json_escape(const char *s) {
    for (; s && *s; s++) {
        switch (*s) {
        case '\\': printf("\\\\"); break;
        case '"': printf("\\\""); break;
        case '\n': printf("\\n"); break;
        case '\r': printf("\\r"); break;
        case '\t': printf("\\t"); break;
        default:
            if ((unsigned char)*s < 0x20) printf("\\u%04x", (unsigned char)*s);
            else putchar(*s);
        }
    }
}

static void print_json(const char *object, const char *entry, const char *status, const char *exit_state) {
    int i;
    printf("{\"object\":\""); json_escape(object); printf("\",");
    printf("\"entry\":\""); json_escape(entry); printf("\",");
    printf("\"status\":\"%s\",\"exit_state\":\"%s\",", status, exit_state);
    printf("\"output\":[");
    for (i = 0; i < g_output_count; i++) {
        if (i) printf(",");
        printf("\""); json_escape(g_output[i]); printf("\"");
    }
    printf("],\"errors\":[");
    for (i = 0; i < g_error_count; i++) {
        if (i) printf(",");
        printf("\""); json_escape(g_error[i]); printf("\"");
    }
    printf("]}\n");
}

static const char *arg_value(int argc, char **argv, const char *name) {
    int i;
    for (i = 1; i + 1 < argc; i++) {
        if (strcmp(argv[i], name) == 0) return argv[i + 1];
    }
    return NULL;
}

int main(int argc, char **argv) {
    const char *object = arg_value(argc, argv, "--object");
    const char *entry = arg_value(argc, argv, "--entry");
    const char *arg_hex = arg_value(argc, argv, "--arg-hex");
    size_t file_size = 0;
    uint8_t *file_base = NULL;
    coff_file_header *hdr;
    coff_section_header *sections;
    coff_symbol *symbols;
    char *string_table;
    size_t string_table_size = 0;
    uint8_t *image = NULL;
    uint8_t **section_bases = NULL;
    size_t image_size = 0;
    size_t section_image_size = 0;
    size_t stub_size = 0x10000;
    resolved_symbol resolved[512] = {0};
    int resolved_count = 0;
    unsigned char *args = NULL;
    int args_len = 0;
    int si;

    if (!object) object = "";
    if (!entry) entry = "go";
    if (!arg_hex) arg_hex = "";
    file_base = (uint8_t *)read_file(object, &file_size);
    if (!file_base || file_size < sizeof(coff_file_header)) {
        add_line(g_error, &g_error_count, "could not read COFF object");
        print_json(object, entry, "fail", "read_error");
        return 1;
    }
    hdr = (coff_file_header *)file_base;
    if (hdr->machine != MACHINE_AMD64) {
        add_line(g_error, &g_error_count, "unsupported machine 0x%04x; expected AMD64", hdr->machine);
        print_json(object, entry, "fail", "bad_arch");
        return 1;
    }
    if (hdr->size_of_optional_header != 0) {
        add_line(g_error, &g_error_count, "not a COFF object: optional header size is %u", hdr->size_of_optional_header);
        print_json(object, entry, "fail", "bad_object");
        return 1;
    }
    sections = (coff_section_header *)(file_base + sizeof(coff_file_header));
    symbols = (coff_symbol *)(file_base + hdr->pointer_to_symbol_table);
    string_table = (char *)(file_base + hdr->pointer_to_symbol_table + hdr->number_of_symbols * sizeof(coff_symbol));
    if ((uint8_t *)string_table + 4 <= file_base + file_size) {
        string_table_size = *(uint32_t *)string_table;
    }
    section_bases = (uint8_t **)calloc(hdr->number_of_sections, sizeof(uint8_t *));
    if (!section_bases) {
        print_json(object, entry, "fail", "oom");
        return 1;
    }
    for (si = 0; si < hdr->number_of_sections; si++) {
        size_t size = sections[si].size_of_raw_data ? sections[si].size_of_raw_data : 1;
        section_image_size += (size + 0xfff) & ~((size_t)0xfff);
    }
    image_size = section_image_size + stub_size;
    image = (uint8_t *)VirtualAlloc(NULL, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!image) {
        add_line(g_error, &g_error_count, "VirtualAlloc failed: %lu", GetLastError());
        print_json(object, entry, "fail", "alloc_error");
        return 1;
    }
    uint8_t *cursor = image;
    for (si = 0; si < hdr->number_of_sections; si++) {
        size_t size = sections[si].size_of_raw_data;
        section_bases[si] = cursor;
        if (size && sections[si].pointer_to_raw_data + size <= file_size) {
            memcpy(cursor, file_base + sections[si].pointer_to_raw_data, size);
        }
        cursor += (size + 0xfff) & ~((size_t)0xfff);
    }
    g_stub_cursor = image + section_image_size;
    g_stub_end = image + image_size;
    if (!apply_relocations(image, sections, hdr->number_of_sections, symbols, hdr->number_of_symbols, string_table, string_table_size, section_bases, file_base, file_size, resolved, &resolved_count)) {
        print_json(object, entry, "fail", "relocation_error");
        return 1;
    }
    uintptr_t entry_addr = 0;
    for (uint32_t i = 0; i < hdr->number_of_symbols; i++) {
        char name_buf[64];
        char *name = symbol_name(&symbols[i], string_table, string_table_size, name_buf, sizeof(name_buf));
        if (strcmp(name, entry) == 0) {
            entry_addr = symbol_address(i, symbols, hdr->number_of_symbols, string_table, string_table_size, section_bases, hdr->number_of_sections, resolved, &resolved_count);
            break;
        }
        i += symbols[i].number_of_aux_symbols;
    }
    if (!entry_addr) {
        add_line(g_error, &g_error_count, "entrypoint not found: %s", entry);
        print_json(object, entry, "fail", "entry_missing");
        return 1;
    }
    args = decode_hex(arg_hex, &args_len);
    if (!args && strlen(arg_hex) > 0) {
        add_line(g_error, &g_error_count, "invalid arg hex");
        print_json(object, entry, "fail", "arg_error");
        return 1;
    }
    typedef void (*bof_entry)(char *, int);
    ((bof_entry)entry_addr)((char *)args, args_len);
    print_json(object, entry, "pass", "success");
    return 0;
}
