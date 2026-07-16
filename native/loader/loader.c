#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "capabilities.generated.h"

#ifdef BOFBENCH_X86
#define MACHINE_LOADER 0x014c
#define LOADER_MACHINE_NAME "I386"
#define REL_LOADER_ABSOLUTE 0x0000
#define REL_LOADER_ADDR32 0x0006
#define REL_LOADER_ADDR32NB 0x0007
#define REL_LOADER_SECTION 0x000a
#define REL_LOADER_SECREL 0x000b
#define REL_LOADER_REL32 0x0014
#else
#define MACHINE_LOADER MACHINE_AMD64
#define LOADER_MACHINE_NAME "AMD64"
#define REL_LOADER_ABSOLUTE REL_AMD64_ABSOLUTE
#define REL_LOADER_ADDR64 REL_AMD64_ADDR64
#define REL_LOADER_ADDR32 REL_AMD64_ADDR32
#define REL_LOADER_ADDR32NB REL_AMD64_ADDR32NB
#define REL_LOADER_SECTION REL_AMD64_SECTION
#define REL_LOADER_SECREL REL_AMD64_SECREL
#define REL_LOADER_REL32 REL_AMD64_REL32
#define REL_LOADER_REL32_1 REL_AMD64_REL32_1
#define REL_LOADER_REL32_2 REL_AMD64_REL32_2
#define REL_LOADER_REL32_3 REL_AMD64_REL32_3
#define REL_LOADER_REL32_4 REL_AMD64_REL32_4
#define REL_LOADER_REL32_5 REL_AMD64_REL32_5
#endif

#define SYM_UNDEFINED 0
#define MAX_FILE_SIZE ((size_t)256 * 1024 * 1024)
#define MAX_IMAGE_SIZE ((size_t)512 * 1024 * 1024)
#define MAX_ARG_BYTES ((size_t)16 * 1024 * 1024)
#define MAX_SECTIONS 4096u
#define MAX_SYMBOLS (1u << 20)
#define MAX_RELOCATIONS (1u << 20)
#define MAX_RESOLVED_SYMBOLS 512
#define MAX_SYMBOL_NAME 1024
#define PAGE_SIZE 0x1000u
#define STUB_SIZE 0x10000u
#define SECTION_MEM_EXECUTE 0x20000000u
#define SECTION_MEM_READ 0x40000000u
#define SECTION_MEM_WRITE 0x80000000u

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
    char *original;
    char *buffer;
    int length;
    int size;
} datap;

typedef struct {
    char *original;
    char *buffer;
    int length;
    int size;
} formatp;

typedef struct {
    char *name;
    uintptr_t value;
    uintptr_t target;
} resolved_symbol;

typedef struct {
    uint8_t *file_base;
    size_t file_size;
    coff_file_header *header;
    coff_section_header *sections;
    coff_symbol *symbols;
    char *string_table;
    size_t string_table_size;
    size_t *section_sizes;
    uint8_t *aux_symbols;
    size_t section_image_size;
    size_t image_size;
} coff_view;

typedef struct {
    uint32_t index;
    char name[9];
    size_t offset;
    size_t mapped_size;
    size_t allocation_size;
    uint32_t characteristics;
    const char *protection;
} memory_section_record;

static char g_output[128][4096];
static int g_output_count = 0;
static char g_error[128][4096];
static int g_error_count = 0;
static char g_error_code[64];
static uint8_t *g_stub_cursor = NULL;
static uint8_t *g_stub_end = NULL;
static memory_section_record g_memory_sections[MAX_SECTIONS];
static uint32_t g_memory_section_count = 0;
static size_t g_stub_offset = 0;
static size_t g_stub_allocation_size = 0;
static const char *g_stub_protection = "";
static uint32_t g_writable_executable_sections = 0;
static int g_memory_ready = 0;
static void json_escape(const char *value);

static void add_error(const char *code, const char *fmt, ...) {
    va_list ap;
    if (g_error_code[0] == 0 && code) {
        snprintf(g_error_code, sizeof(g_error_code), "%s", code);
    }
    if (g_error_count >= 128) return;
    va_start(ap, fmt);
    vsnprintf(g_error[g_error_count], sizeof(g_error[g_error_count]), fmt, ap);
    va_end(ap);
    g_error_count++;
}

static void add_output(const char *fmt, ...) {
    va_list ap;
    if (g_output_count >= 128) return;
    va_start(ap, fmt);
    vsnprintf(g_output[g_output_count], sizeof(g_output[g_output_count]), fmt, ap);
    va_end(ap);
    printf("{\"protocol_event\":\"beacon_output\",\"line\":\"");
    json_escape(g_output[g_output_count]);
    printf("\"}\n");
    fflush(stdout);
    g_output_count++;
}

static int parser_has(datap *parser, int amount) {
    return parser && parser->buffer && amount >= 0 && parser->length >= amount;
}

void BeaconDataParse(datap *parser, char *buffer, int size) {
    int declared = 0;
    if (!parser) return;
    parser->original = buffer;
    parser->buffer = NULL;
    parser->length = 0;
    parser->size = 0;
    if (!buffer || size < 4) return;
    memcpy(&declared, buffer, 4);
    if (declared < 0 || declared > size - 4) return;
    parser->buffer = buffer + 4;
    parser->length = declared;
    parser->size = declared;
}

int BeaconDataInt(datap *parser) {
    int out = 0;
    if (!parser_has(parser, 4)) return 0;
    memcpy(&out, parser->buffer, 4);
    parser->buffer += 4;
    parser->length -= 4;
    return out;
}

short BeaconDataShort(datap *parser) {
    short out = 0;
    if (!parser_has(parser, 2)) return 0;
    memcpy(&out, parser->buffer, 2);
    parser->buffer += 2;
    parser->length -= 2;
    return out;
}

int BeaconDataLength(datap *parser) {
    if (!parser || parser->length < 0) return 0;
    return parser->length;
}

char *BeaconDataExtract(datap *parser, int *size) {
    int len = 0;
    char *out;
    if (size) *size = 0;
    if (!parser_has(parser, 4)) return NULL;
    memcpy(&len, parser->buffer, 4);
    parser->buffer += 4;
    parser->length -= 4;
    if (len < 0 || !parser_has(parser, len)) return NULL;
    out = parser->buffer;
    parser->buffer += len;
    parser->length -= len;
    if (size) *size = len;
    return out;
}

void BeaconOutput(int type, char *data, int len) {
    char tmp[4096];
    int n;
    (void)type;
    if (!data || len <= 0) {
        add_output("");
        return;
    }
    n = len < (int)sizeof(tmp) - 1 ? len : (int)sizeof(tmp) - 1;
    memcpy(tmp, data, (size_t)n);
    tmp[n] = 0;
    add_output("%s", tmp);
}

void BeaconPrintf(int type, const char *fmt, ...) {
    char tmp[4096];
    va_list ap;
    (void)type;
    if (!fmt) return;
    va_start(ap, fmt);
    vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    add_output("%s", tmp);
}

void BeaconFormatAlloc(formatp *format, int maxsz) {
    if (!format) return;
    memset(format, 0, sizeof(*format));
    if (maxsz <= 0) return;
    format->original = (char *)calloc(1, (size_t)maxsz);
    if (!format->original) return;
    format->buffer = format->original;
    format->size = maxsz;
}

void BeaconFormatReset(formatp *format) {
    if (!format || !format->original || format->size <= 0) return;
    memset(format->original, 0, (size_t)format->size);
    format->buffer = format->original;
    format->length = 0;
}

void BeaconFormatFree(formatp *format) {
    if (!format) return;
    free(format->original);
    memset(format, 0, sizeof(*format));
}

void BeaconFormatAppend(formatp *format, char *text, int len) {
    if (!format || !format->original || !text || len <= 0 || format->length < 0 || format->size < 0 || format->length > format->size) return;
    if (len > format->size - format->length) len = format->size - format->length;
    if (len <= 0) return;
    memcpy(format->original + format->length, text, (size_t)len);
    format->length += len;
    format->buffer = format->original + format->length;
}

void BeaconFormatPrintf(formatp *format, const char *fmt, ...) {
    va_list ap;
    int available;
    int written;
    if (!format || !format->original || !fmt || format->length < 0 || format->size <= format->length) return;
    available = format->size - format->length;
    va_start(ap, fmt);
    written = vsnprintf(format->original + format->length, (size_t)available, fmt, ap);
    va_end(ap);
    if (written < 0) return;
    if (written >= available) written = available - 1;
    format->length += written;
    format->buffer = format->original + format->length;
}

char *BeaconFormatToString(formatp *format, int *size) {
    if (size) *size = 0;
    if (!format || !format->original || format->length < 0) return NULL;
    if (size) *size = format->length;
    return format->original;
}

void BeaconFormatInt(formatp *format, int value) {
    unsigned char encoded[4];
    encoded[0] = (unsigned char)(((uint32_t)value >> 24) & 0xff);
    encoded[1] = (unsigned char)(((uint32_t)value >> 16) & 0xff);
    encoded[2] = (unsigned char)(((uint32_t)value >> 8) & 0xff);
    encoded[3] = (unsigned char)((uint32_t)value & 0xff);
    BeaconFormatAppend(format, (char *)encoded, 4);
}

static int range_within(size_t total, uint64_t offset, uint64_t length) {
    uint64_t total64 = (uint64_t)total;
    return offset <= total64 && length <= total64 - offset;
}

static int align_page(size_t value, size_t *out) {
    if (value > SIZE_MAX - (PAGE_SIZE - 1)) return 0;
    *out = (value + (PAGE_SIZE - 1)) & ~((size_t)PAGE_SIZE - 1);
    return 1;
}

static void *read_file(const char *path, size_t *out_size) {
    FILE *file;
    void *buffer;
    long length;
    *out_size = 0;
    file = fopen(path, "rb");
    if (!file) {
        add_error("file_open", "could not open COFF object: %s", path);
        return NULL;
    }
    if (fseek(file, 0, SEEK_END) != 0 || (length = ftell(file)) < 0 || fseek(file, 0, SEEK_SET) != 0) {
        add_error("file_size", "could not determine COFF object size");
        fclose(file);
        return NULL;
    }
    if (length == 0) {
        add_error("file_empty", "COFF object is empty");
        fclose(file);
        return NULL;
    }
    if ((uint64_t)length > (uint64_t)MAX_FILE_SIZE) {
        add_error("file_size_limit", "COFF object exceeds the %u MiB loader limit", (unsigned)(MAX_FILE_SIZE / 1024 / 1024));
        fclose(file);
        return NULL;
    }
    buffer = calloc(1, (size_t)length);
    if (!buffer) {
        add_error("oom", "could not allocate memory for COFF object");
        fclose(file);
        return NULL;
    }
    if (fread(buffer, 1, (size_t)length, file) != (size_t)length) {
        add_error("file_read", "could not read complete COFF object");
        free(buffer);
        fclose(file);
        return NULL;
    }
    fclose(file);
    *out_size = (size_t)length;
    return buffer;
}

static int hex_value(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static unsigned char *decode_hex(const char *hex, int *out_len) {
    size_t length = hex ? strlen(hex) : 0;
    unsigned char *out;
    size_t index;
    *out_len = 0;
    if (length > MAX_ARG_BYTES * 2 || length / 2 > (size_t)INT_MAX) {
        add_error("arg_size_limit", "packed argument data exceeds the %u MiB loader limit", (unsigned)(MAX_ARG_BYTES / 1024 / 1024));
        return NULL;
    }
    if (length % 2 != 0) {
        add_error("arg_hex_length", "packed argument hex has odd length");
        return NULL;
    }
    out = (unsigned char *)calloc(1, length / 2 + 1);
    if (!out) {
        add_error("oom", "could not allocate packed argument buffer");
        return NULL;
    }
    for (index = 0; index < length; index += 2) {
        int high = hex_value(hex[index]);
        int low = hex_value(hex[index + 1]);
        if (high < 0 || low < 0) {
            add_error("arg_hex_character", "packed argument hex contains a non-hex character at byte %u", (unsigned)index);
            free(out);
            return NULL;
        }
        out[index / 2] = (unsigned char)((high << 4) | low);
    }
    *out_len = (int)(length / 2);
    return out;
}

static int copy_symbol_name(const coff_symbol *symbol, const char *string_table, size_t string_table_size, char *buffer, size_t buffer_size) {
    size_t length;
    const char *start;
    const char *end;
    if (!symbol || !buffer || buffer_size == 0) return 0;
    buffer[0] = 0;
    if (symbol->name.long_name.zeroes == 0) {
        uint32_t offset = symbol->name.long_name.offset;
        if (!string_table || offset < 4 || offset >= string_table_size) {
            add_error("symbol_name_offset", "symbol string-table offset %u is outside object bounds", offset);
            return 0;
        }
        start = string_table + offset;
        end = (const char *)memchr(start, 0, string_table_size - offset);
        if (!end) {
            add_error("symbol_name_termination", "symbol name at string-table offset %u is not NUL-terminated", offset);
            return 0;
        }
        length = (size_t)(end - start);
    } else {
        start = (const char *)symbol->name.short_name;
        end = (const char *)memchr(start, 0, 8);
        length = end ? (size_t)(end - start) : 8;
    }
    if (length >= buffer_size || length > MAX_SYMBOL_NAME) {
        add_error("symbol_name_limit", "symbol name exceeds the %u-byte loader limit", (unsigned)MAX_SYMBOL_NAME);
        return 0;
    }
    memcpy(buffer, start, length);
    buffer[length] = 0;
    return 1;
}

static const char *loader_relocation_name(uint16_t type) {
#ifdef BOFBENCH_X86
    switch (type) {
    case REL_LOADER_ABSOLUTE: return "ABSOLUTE";
    case REL_LOADER_ADDR32: return "DIR32";
    case REL_LOADER_ADDR32NB: return "DIR32NB";
    case REL_LOADER_SECTION: return "SECTION";
    case REL_LOADER_SECREL: return "SECREL";
    case REL_LOADER_REL32: return "REL32";
    default: return "UNKNOWN";
    }
#else
    return bofbench_relocation_type_name(type);
#endif
}

static int loader_relocation_supported(uint16_t type) {
#ifdef BOFBENCH_X86
    return type == REL_LOADER_ABSOLUTE || type == REL_LOADER_ADDR32 || type == REL_LOADER_ADDR32NB || type == REL_LOADER_SECTION || type == REL_LOADER_SECREL || type == REL_LOADER_REL32;
#else
    return bofbench_relocation_is_supported(type);
#endif
}

static size_t relocation_width(uint16_t type) {
    if (type == REL_LOADER_ABSOLUTE) return 0;
#ifndef BOFBENCH_X86
    if (type == REL_LOADER_ADDR64) return 8;
#endif
    if (type == REL_LOADER_SECTION) return 2;
    return 4;
}

static int validate_coff(uint8_t *file_base, size_t file_size, coff_view *view) {
    coff_file_header *header;
    uint64_t section_table_size;
    uint64_t section_table_end;
    uint64_t total_relocations = 0;
    uint32_t section_index;
    memset(view, 0, sizeof(*view));
    view->file_base = file_base;
    view->file_size = file_size;
    if (!range_within(file_size, 0, sizeof(coff_file_header))) {
        add_error("header_range", "file is too small for a COFF header");
        return 0;
    }
    header = (coff_file_header *)file_base;
    view->header = header;
    if (header->number_of_sections == 0) {
        add_error("section_table_empty", "COFF object declares no sections");
        return 0;
    }
    if (header->number_of_sections > MAX_SECTIONS) {
        add_error("section_count_limit", "COFF object declares %u sections; loader limit is %u", header->number_of_sections, MAX_SECTIONS);
        return 0;
    }
    section_table_size = (uint64_t)header->number_of_sections * sizeof(coff_section_header);
    section_table_end = sizeof(coff_file_header) + section_table_size;
    if (!range_within(file_size, sizeof(coff_file_header), section_table_size)) {
        add_error("section_table_range", "section table extends beyond object bounds");
        return 0;
    }
    view->sections = (coff_section_header *)(file_base + sizeof(coff_file_header));
    view->section_sizes = (size_t *)calloc(header->number_of_sections, sizeof(size_t));
    if (!view->section_sizes) {
        add_error("oom", "could not allocate section-size table");
        return 0;
    }
    for (section_index = 0; section_index < header->number_of_sections; section_index++) {
        coff_section_header *section = &view->sections[section_index];
        size_t mapped_size = section->size_of_raw_data;
        size_t allocation_size;
        size_t aligned_size;
        uint64_t relocation_bytes;
        if (section->virtual_size > mapped_size) mapped_size = section->virtual_size;
        view->section_sizes[section_index] = mapped_size;
        if (!(section->characteristics & SECTION_CNT_UNINITIALIZED_DATA)) {
            if (section->size_of_raw_data > 0) {
                if (section->pointer_to_raw_data == 0) {
                    add_error("section_data_pointer", "section %u declares data with a zero file pointer", section_index + 1);
                    return 0;
                }
                if (!range_within(file_size, section->pointer_to_raw_data, section->size_of_raw_data)) {
                    add_error("section_data_range", "section %u raw data extends beyond object bounds", section_index + 1);
                    return 0;
                }
                if ((uint64_t)section->pointer_to_raw_data < section_table_end) {
                    add_error("section_data_overlap_headers", "section %u raw data overlaps COFF headers", section_index + 1);
                    return 0;
                }
            } else if (section->virtual_size > 0) {
                add_error("section_data_missing", "initialized section %u declares virtual bytes without raw data", section_index + 1);
                return 0;
            }
        }
        allocation_size = mapped_size ? mapped_size : 1;
        if (!align_page(allocation_size, &aligned_size) || aligned_size > MAX_IMAGE_SIZE - view->section_image_size) {
            add_error("image_size_limit", "mapped section image exceeds the %u MiB loader limit", (unsigned)(MAX_IMAGE_SIZE / 1024 / 1024));
            return 0;
        }
        view->section_image_size += aligned_size;
        if (section->number_of_relocations == 0) continue;
        relocation_bytes = (uint64_t)section->number_of_relocations * sizeof(coff_relocation);
        total_relocations += section->number_of_relocations;
        if (total_relocations > MAX_RELOCATIONS) {
            add_error("relocation_count_limit", "COFF object exceeds the %u-relocation loader limit", MAX_RELOCATIONS);
            return 0;
        }
        if (section->pointer_to_relocations == 0) {
            add_error("relocation_table_pointer", "section %u declares relocations with a zero table pointer", section_index + 1);
            return 0;
        }
        if (!range_within(file_size, section->pointer_to_relocations, relocation_bytes)) {
            add_error("relocation_table_range", "relocation table for section %u extends beyond object bounds", section_index + 1);
            return 0;
        }
        if ((uint64_t)section->pointer_to_relocations < section_table_end) {
            add_error("relocation_table_overlap_headers", "relocation table for section %u overlaps COFF headers", section_index + 1);
            return 0;
        }
    }
    if (view->section_image_size > MAX_IMAGE_SIZE - STUB_SIZE) {
        add_error("image_size_limit", "mapped image and external stubs exceed the %u MiB loader limit", (unsigned)(MAX_IMAGE_SIZE / 1024 / 1024));
        return 0;
    }
    view->image_size = view->section_image_size + STUB_SIZE;

    if (header->number_of_symbols > MAX_SYMBOLS) {
        add_error("symbol_count_limit", "COFF object declares %u symbols; loader limit is %u", header->number_of_symbols, MAX_SYMBOLS);
        return 0;
    }
    if (header->number_of_symbols > 0) {
        uint64_t symbol_bytes = (uint64_t)header->number_of_symbols * sizeof(coff_symbol);
        uint64_t string_start;
        uint32_t string_size = 0;
        uint32_t symbol_index;
        if (header->pointer_to_symbol_table == 0) {
            add_error("symbol_table_pointer", "COFF object declares symbols with a zero table pointer");
            return 0;
        }
        if (!range_within(file_size, header->pointer_to_symbol_table, symbol_bytes)) {
            add_error("symbol_table_range", "symbol table extends beyond object bounds");
            return 0;
        }
        if ((uint64_t)header->pointer_to_symbol_table < section_table_end) {
            add_error("symbol_table_overlap_headers", "symbol table overlaps COFF headers");
            return 0;
        }
        view->symbols = (coff_symbol *)(file_base + header->pointer_to_symbol_table);
        string_start = (uint64_t)header->pointer_to_symbol_table + symbol_bytes;
        if (range_within(file_size, string_start, 4)) {
            memcpy(&string_size, file_base + (size_t)string_start, sizeof(string_size));
            if (string_size < 4) {
                add_error("string_table_length", "COFF string-table length %u is smaller than 4", string_size);
                return 0;
            }
            if (!range_within(file_size, string_start, string_size)) {
                add_error("string_table_range", "COFF string table extends beyond object bounds");
                return 0;
            }
            view->string_table = (char *)(file_base + (size_t)string_start);
            view->string_table_size = string_size;
        }
        view->aux_symbols = (uint8_t *)calloc(header->number_of_symbols, 1);
        if (!view->aux_symbols) {
            add_error("oom", "could not allocate auxiliary-symbol map");
            return 0;
        }
        for (symbol_index = 0; symbol_index < header->number_of_symbols;) {
            coff_symbol *symbol = &view->symbols[symbol_index];
            uint32_t aux_count = symbol->number_of_aux_symbols;
            uint64_t next = (uint64_t)symbol_index + 1 + aux_count;
            uint32_t aux_index;
            char name[MAX_SYMBOL_NAME + 1];
            if (!copy_symbol_name(symbol, view->string_table, view->string_table_size, name, sizeof(name))) return 0;
            if (next > header->number_of_symbols) {
                add_error("aux_symbol_range", "symbol %u declares %u auxiliary records beyond the symbol table", symbol_index, aux_count);
                return 0;
            }
            for (aux_index = 1; aux_index <= aux_count; aux_index++) view->aux_symbols[symbol_index + aux_index] = 1;
            if (symbol->section_number > (int16_t)header->number_of_sections || symbol->section_number < -2) {
                add_error("symbol_section_range", "symbol %u refers to invalid section %d", symbol_index, symbol->section_number);
                return 0;
            }
            if (symbol->section_number > 0 && symbol->value > view->section_sizes[symbol->section_number - 1]) {
                add_error("symbol_value_range", "symbol %u value 0x%x exceeds section %d size", symbol_index, symbol->value, symbol->section_number);
                return 0;
            }
            symbol_index = (uint32_t)next;
        }
    }

    for (section_index = 0; section_index < header->number_of_sections; section_index++) {
        coff_section_header *section = &view->sections[section_index];
        coff_relocation *relocations;
        uint32_t relocation_index;
        if (section->number_of_relocations == 0) continue;
        relocations = (coff_relocation *)(file_base + section->pointer_to_relocations);
        for (relocation_index = 0; relocation_index < section->number_of_relocations; relocation_index++) {
            coff_relocation *relocation = &relocations[relocation_index];
            size_t width;
            if (relocation->symbol_table_index >= header->number_of_symbols) {
                add_error("relocation_symbol_range", "relocation %u in section %u refers to symbol %u outside the table", relocation_index, section_index + 1, relocation->symbol_table_index);
                return 0;
            }
            if (view->aux_symbols && view->aux_symbols[relocation->symbol_table_index]) {
                add_error("relocation_aux_symbol", "relocation %u in section %u refers to an auxiliary symbol", relocation_index, section_index + 1);
                return 0;
            }
            if (!loader_relocation_supported(relocation->type)) {
                add_error("unsupported_relocation", "unsupported %s relocation %s/0x%04x in section %u", LOADER_MACHINE_NAME, loader_relocation_name(relocation->type), relocation->type, section_index + 1);
                return 0;
            }
            width = relocation_width(relocation->type);
            if ((size_t)relocation->virtual_address > view->section_sizes[section_index] || width > view->section_sizes[section_index] - (size_t)relocation->virtual_address) {
                add_error("relocation_offset_range", "%s relocation at 0x%x needs %u bytes in section %u of size 0x%llx", loader_relocation_name(relocation->type), relocation->virtual_address, (unsigned)width, section_index + 1, (unsigned long long)view->section_sizes[section_index]);
                return 0;
            }
        }
    }
    return 1;
}

static HMODULE load_symbol_library(const char *library) {
    char dll[MAX_SYMBOL_NAME + 8];
    if (snprintf(dll, sizeof(dll), "%s.dll", library) < 0) return NULL;
    return LoadLibraryA(dll);
}

static uintptr_t alloc_near_data_ptr(uintptr_t target) {
    uint8_t *slot;
    if (!g_stub_cursor || !g_stub_end || g_stub_cursor > g_stub_end || (size_t)(g_stub_end - g_stub_cursor) < 16) return 0;
    slot = g_stub_cursor;
    memset(slot, 0, 16);
    memcpy(slot, &target, sizeof(target));
    g_stub_cursor += 16;
    return (uintptr_t)slot;
}

static uintptr_t alloc_near_jump_stub(uintptr_t target) {
    uint8_t *stub;
    if (!g_stub_cursor || !g_stub_end || g_stub_cursor > g_stub_end || (size_t)(g_stub_end - g_stub_cursor) < 16) return 0;
    stub = g_stub_cursor;
    memset(stub, 0x90, 16);
#ifdef BOFBENCH_X86
    stub[0] = 0xB8;
    memcpy(stub + 1, &target, sizeof(target));
    stub[5] = 0xFF;
    stub[6] = 0xE0;
#else
    stub[0] = 0x48;
    stub[1] = 0xB8;
    memcpy(stub + 2, &target, sizeof(target));
    stub[10] = 0xFF;
    stub[11] = 0xE0;
#endif
    g_stub_cursor += 16;
    return (uintptr_t)stub;
}

static uintptr_t cache_external_value(const char *name, uintptr_t target, resolved_symbol *resolved, int *resolved_count) {
    uintptr_t value;
    char *copy;
    if (!target) return 0;
    if (*resolved_count >= MAX_RESOLVED_SYMBOLS) {
        add_error("resolved_symbol_limit", "external symbol cache exceeds %u entries", MAX_RESOLVED_SYMBOLS);
        return 0;
    }
    value = bofbench_is_import_pointer_symbol(name) ? alloc_near_data_ptr(target) : alloc_near_jump_stub(target);
    if (!value) {
        add_error("external_stub_limit", "external stub area exhausted while resolving %s", name);
        return 0;
    }
    copy = _strdup(name);
    if (!copy) {
        add_error("oom", "could not retain resolved symbol name");
        return 0;
    }
    resolved[*resolved_count].name = copy;
    resolved[*resolved_count].target = target;
    resolved[*resolved_count].value = value;
    (*resolved_count)++;
    return value;
}

static uintptr_t resolve_winapi_target(const char *name) {
    char copy[MAX_SYMBOL_NAME + 1];
    char *function;
    char *dollar;
    size_t index;
    if (strlen(name) > MAX_SYMBOL_NAME) return 0;
    snprintf(copy, sizeof(copy), "%s", name);
    function = (char *)bofbench_normalize_import(copy);
    dollar = strchr(function, '$');
    if (dollar) {
        HMODULE module;
        *dollar = 0;
        module = load_symbol_library(function);
        if (!module) return 0;
        return (uintptr_t)GetProcAddress(module, dollar + 1);
    }
    {
        const char *library = bofbench_symbol_import_library(function);
        if (library) {
            HMODULE module = load_symbol_library(library);
            if (!module) return 0;
            return (uintptr_t)GetProcAddress(module, function);
        }
    }
    for (index = 0; index < sizeof(bofbench_fallback_libraries) / sizeof(bofbench_fallback_libraries[0]); index++) {
        HMODULE module = load_symbol_library(bofbench_fallback_libraries[index]);
        FARPROC procedure;
        if (!module) continue;
        procedure = GetProcAddress(module, function);
        if (procedure) return (uintptr_t)procedure;
    }
    return 0;
}

static uintptr_t resolve_external(const char *name, resolved_symbol *resolved, int *resolved_count) {
    int index;
    uintptr_t target = 0;
    const char *normalized = bofbench_normalize_import(name);
#ifdef BOFBENCH_X86
    char decorated[MAX_SYMBOL_NAME + 1];
    char *suffix;
    size_t suffix_index;
    snprintf(decorated, sizeof(decorated), "%s", normalized[0] == '_' ? normalized + 1 : normalized);
    suffix = strrchr(decorated, '@');
    if (suffix && suffix[1] != 0) {
        int numeric = 1;
        for (suffix_index = 1; suffix[suffix_index] != 0; suffix_index++) {
            if (suffix[suffix_index] < '0' || suffix[suffix_index] > '9') {
                numeric = 0;
                break;
            }
        }
        if (numeric) *suffix = 0;
    }
    normalized = decorated;
#endif
    for (index = 0; index < *resolved_count; index++) {
        if (strcmp(resolved[index].name, name) == 0) return resolved[index].value;
    }
#define TRY_BEACON_API(api) if (!target && strcmp(normalized, #api) == 0) target = (uintptr_t)api;
    BOFBENCH_BEACON_API_LIST(TRY_BEACON_API)
#undef TRY_BEACON_API
    if (!target) target = resolve_winapi_target(normalized);
    return cache_external_value(name, target, resolved, resolved_count);
}

static uintptr_t symbol_address(const coff_view *view, uint32_t index, uint8_t **section_bases, resolved_symbol *resolved, int *resolved_count) {
    char name[MAX_SYMBOL_NAME + 1];
    coff_symbol *symbol;
    if (index >= view->header->number_of_symbols || (view->aux_symbols && view->aux_symbols[index])) return 0;
    symbol = &view->symbols[index];
    if (!copy_symbol_name(symbol, view->string_table, view->string_table_size, name, sizeof(name))) return 0;
    if (symbol->section_number > 0 && symbol->section_number <= (int16_t)view->header->number_of_sections) {
        if (symbol->value > view->section_sizes[symbol->section_number - 1]) return 0;
        return (uintptr_t)(section_bases[symbol->section_number - 1] + symbol->value);
    }
    if (symbol->section_number == SYM_UNDEFINED) return resolve_external(name, resolved, resolved_count);
    return 0;
}

static int apply_relocations(const coff_view *view, uint8_t *image_base, uint8_t **section_bases, resolved_symbol *resolved, int *resolved_count) {
    uint32_t section_index;
    for (section_index = 0; section_index < view->header->number_of_sections; section_index++) {
        coff_section_header *section = &view->sections[section_index];
        coff_relocation *relocations;
        uint32_t relocation_index;
        uint64_t relocation_bytes = (uint64_t)section->number_of_relocations * sizeof(coff_relocation);
        if (section->number_of_relocations == 0) continue;
        if (!range_within(view->file_size, section->pointer_to_relocations, relocation_bytes)) {
            add_error("relocation_table_range", "relocation table for section %u is outside object bounds", section_index + 1);
            return 0;
        }
        relocations = (coff_relocation *)(view->file_base + section->pointer_to_relocations);
        for (relocation_index = 0; relocation_index < section->number_of_relocations; relocation_index++) {
            char symbol_name[MAX_SYMBOL_NAME + 1];
            coff_relocation *relocation = &relocations[relocation_index];
            coff_symbol *symbol = &view->symbols[relocation->symbol_table_index];
            size_t width = relocation_width(relocation->type);
            uint8_t *where;
            uintptr_t target = 0;
            if ((size_t)relocation->virtual_address > view->section_sizes[section_index] || width > view->section_sizes[section_index] - (size_t)relocation->virtual_address) {
                add_error("relocation_offset_range", "relocation %u in section %u writes outside the mapped section", relocation_index, section_index + 1);
                return 0;
            }
            if (!copy_symbol_name(&view->symbols[relocation->symbol_table_index], view->string_table, view->string_table_size, symbol_name, sizeof(symbol_name))) return 0;
            where = section_bases[section_index] + relocation->virtual_address;
            if (relocation->type == REL_LOADER_SECTION || relocation->type == REL_LOADER_SECREL) {
                if (symbol->section_number <= 0 || symbol->section_number > (int16_t)view->header->number_of_sections) {
                    add_error("relocation_symbol_section", "%s relocation requires a defined section symbol: %s", loader_relocation_name(relocation->type), symbol_name);
                    return 0;
                }
            } else if (relocation->type != REL_LOADER_ABSOLUTE) {
                target = symbol_address(view, relocation->symbol_table_index, section_bases, resolved, resolved_count);
                if (!target) {
                    add_error("unresolved_symbol", "unresolved symbol %s (index %u, relocation %s/0x%04x, section %.*s+0x%x)", symbol_name, relocation->symbol_table_index, loader_relocation_name(relocation->type), relocation->type, 8, section->name, relocation->virtual_address);
                    return 0;
                }
            }
            switch (relocation->type) {
            case REL_LOADER_ABSOLUTE:
                break;
#ifndef BOFBENCH_X86
            case REL_LOADER_ADDR64: {
                uint64_t addend;
                uint64_t value;
                memcpy(&addend, where, sizeof(addend));
                if (addend > UINT64_MAX - (uint64_t)target) {
                    add_error("relocation_overflow", "ADDR64 relocation overflows for symbol %s", symbol_name);
                    return 0;
                }
                value = (uint64_t)target + addend;
                memcpy(where, &value, sizeof(value));
                break;
            }
#endif
            case REL_LOADER_ADDR32: {
                uint32_t addend;
                uint64_t value;
                memcpy(&addend, where, sizeof(addend));
                value = (uint64_t)target + addend;
                if (value > UINT32_MAX) {
                    add_error("relocation_overflow", "ADDR32 relocation overflows for symbol %s", symbol_name);
                    return 0;
                }
                addend = (uint32_t)value;
                memcpy(where, &addend, sizeof(addend));
                break;
            }
            case REL_LOADER_ADDR32NB: {
                uint32_t addend;
                uint64_t value;
                if (target < (uintptr_t)image_base) {
                    add_error("relocation_overflow", "ADDR32NB target precedes image for symbol %s", symbol_name);
                    return 0;
                }
                memcpy(&addend, where, sizeof(addend));
                value = (uint64_t)(target - (uintptr_t)image_base) + addend;
                if (value > UINT32_MAX) {
                    add_error("relocation_overflow", "ADDR32NB relocation overflows for symbol %s", symbol_name);
                    return 0;
                }
                addend = (uint32_t)value;
                memcpy(where, &addend, sizeof(addend));
                break;
            }
            case REL_LOADER_SECTION: {
                uint16_t addend;
                uint32_t value;
                memcpy(&addend, where, sizeof(addend));
                value = (uint32_t)addend + (uint32_t)symbol->section_number;
                if (value > UINT16_MAX) {
                    add_error("relocation_overflow", "SECTION relocation overflows for symbol %s", symbol_name);
                    return 0;
                }
                addend = (uint16_t)value;
                memcpy(where, &addend, sizeof(addend));
                break;
            }
            case REL_LOADER_SECREL: {
                uint32_t addend;
                uint64_t value;
                memcpy(&addend, where, sizeof(addend));
                value = (uint64_t)addend + symbol->value;
                if (value > UINT32_MAX) {
                    add_error("relocation_overflow", "SECREL relocation overflows for symbol %s", symbol_name);
                    return 0;
                }
                addend = (uint32_t)value;
                memcpy(where, &addend, sizeof(addend));
                break;
            }
            case REL_LOADER_REL32:
#ifndef BOFBENCH_X86
            case REL_LOADER_REL32_1:
            case REL_LOADER_REL32_2:
            case REL_LOADER_REL32_3:
            case REL_LOADER_REL32_4:
            case REL_LOADER_REL32_5:
#endif
            {
                int32_t addend;
                int32_t encoded;
                int adjust = 4 + (relocation->type - REL_LOADER_REL32);
                int64_t displacement;
                memcpy(&addend, where, sizeof(addend));
                displacement = (int64_t)target + addend - ((int64_t)(uintptr_t)where + adjust);
                if (displacement < INT32_MIN || displacement > INT32_MAX) {
                    add_error("relocation_overflow", "%s displacement overflows for symbol %s", loader_relocation_name(relocation->type), symbol_name);
                    return 0;
                }
                encoded = (int32_t)displacement;
                memcpy(where, &encoded, sizeof(encoded));
                break;
            }
            default:
                add_error("unsupported_relocation", "unsupported %s relocation %s/0x%04x for symbol %s", LOADER_MACHINE_NAME, loader_relocation_name(relocation->type), relocation->type, symbol_name);
                return 0;
            }
        }
    }
    return 1;
}

static DWORD section_protection(uint32_t characteristics) {
    int executable = (characteristics & SECTION_MEM_EXECUTE) != 0;
    int readable = (characteristics & SECTION_MEM_READ) != 0;
    int writable = (characteristics & SECTION_MEM_WRITE) != 0;
    if (executable && writable) return PAGE_EXECUTE_READWRITE;
    if (executable && readable) return PAGE_EXECUTE_READ;
    if (executable) return PAGE_EXECUTE;
    if (writable) return PAGE_READWRITE;
    return PAGE_READONLY;
}

static const char *protection_name(DWORD protection) {
    switch (protection) {
    case PAGE_EXECUTE: return "execute";
    case PAGE_EXECUTE_READ: return "execute_read";
    case PAGE_EXECUTE_READWRITE: return "execute_readwrite";
    case PAGE_READWRITE: return "readwrite";
    case PAGE_READONLY: return "readonly";
    case PAGE_NOACCESS: return "noaccess";
    default: return "unknown";
    }
}

static void copy_section_name(const coff_section_header *section, char name[9]) {
    size_t length = 8;
    const uint8_t *zero = (const uint8_t *)memchr(section->name, 0, 8);
    if (zero) length = (size_t)(zero - section->name);
    memcpy(name, section->name, length);
    name[length] = 0;
}

static int protect_image(const coff_view *view, uint8_t *image, uint8_t **section_bases) {
    uint32_t section_index;
    DWORD previous;
    g_memory_section_count = 0;
    g_writable_executable_sections = 0;
    for (section_index = 0; section_index < view->header->number_of_sections; section_index++) {
        coff_section_header *section = &view->sections[section_index];
        size_t allocation_size = view->section_sizes[section_index] ? view->section_sizes[section_index] : 1;
        size_t aligned_size;
        DWORD protection = section_protection(section->characteristics);
        memory_section_record *record;
        if (!align_page(allocation_size, &aligned_size)) {
            add_error("image_size_overflow", "section protection alignment overflow");
            return 0;
        }
        if (!VirtualProtect(section_bases[section_index], aligned_size, protection, &previous)) {
            add_error("section_protect", "VirtualProtect failed for section %u: %lu", section_index + 1, GetLastError());
            return 0;
        }
        record = &g_memory_sections[g_memory_section_count++];
        record->index = section_index + 1;
        copy_section_name(section, record->name);
        record->offset = (size_t)(section_bases[section_index] - image);
        record->mapped_size = view->section_sizes[section_index];
        record->allocation_size = aligned_size;
        record->characteristics = section->characteristics;
        record->protection = protection_name(protection);
        if ((section->characteristics & SECTION_MEM_EXECUTE) && (section->characteristics & SECTION_MEM_WRITE)) {
            g_writable_executable_sections++;
        }
    }
    if (!VirtualProtect(image + view->section_image_size, STUB_SIZE, PAGE_EXECUTE_READ, &previous)) {
        add_error("stub_protect", "VirtualProtect failed for external stub region: %lu", GetLastError());
        return 0;
    }
    g_stub_offset = view->section_image_size;
    g_stub_allocation_size = STUB_SIZE;
    g_stub_protection = protection_name(PAGE_EXECUTE_READ);
    g_memory_ready = 1;
    return 1;
}

static void json_escape(const char *value) {
    for (; value && *value; value++) {
        switch (*value) {
        case '\\': printf("\\\\"); break;
        case '"': printf("\\\""); break;
        case '\n': printf("\\n"); break;
        case '\r': printf("\\r"); break;
        case '\t': printf("\\t"); break;
        default:
            if ((unsigned char)*value < 0x20) printf("\\u%04x", (unsigned char)*value);
            else putchar(*value);
        }
    }
}

static void print_memory_json(void) {
    uint32_t index;
    printf("{\"initial_protection\":\"readwrite\",\"sections\":[");
    for (index = 0; index < g_memory_section_count; index++) {
        memory_section_record *record = &g_memory_sections[index];
        if (index) printf(",");
        printf("{\"index\":%u,\"name\":\"", record->index); json_escape(record->name);
        printf("\",\"offset\":%llu,\"mapped_size\":%llu,\"allocation_size\":%llu,\"characteristics\":%u,\"protection\":\"%s\"}",
            (unsigned long long)record->offset,
            (unsigned long long)record->mapped_size,
            (unsigned long long)record->allocation_size,
            record->characteristics,
            record->protection);
    }
    printf("],\"stub_region\":{\"offset\":%llu,\"allocation_size\":%llu,\"protection\":\"%s\"},\"writable_executable_sections\":%u}",
        (unsigned long long)g_stub_offset,
        (unsigned long long)g_stub_allocation_size,
        g_stub_protection,
        g_writable_executable_sections);
}

static void print_memory_event(void) {
    if (!g_memory_ready) return;
    printf("{\"protocol_event\":\"memory_protect\",\"memory\":");
    print_memory_json();
    printf("}\n");
    fflush(stdout);
}

static void print_json(const char *object, const char *entry, const char *status, const char *exit_state) {
    int index;
    printf("{\"object\":\""); json_escape(object); printf("\",");
    printf("\"entry\":\""); json_escape(entry); printf("\",");
    printf("\"status\":\"%s\",\"exit_state\":\"%s\",", status, exit_state);
    printf("\"error_code\":\""); json_escape(g_error_code); printf("\",");
    if (g_memory_ready) {
        printf("\"memory\":"); print_memory_json(); printf(",");
    }
    printf("\"output\":[");
    for (index = 0; index < g_output_count; index++) {
        if (index) printf(",");
        printf("\""); json_escape(g_output[index]); printf("\"");
    }
    printf("],\"errors\":[");
    for (index = 0; index < g_error_count; index++) {
        if (index) printf(",");
        printf("\""); json_escape(g_error[index]); printf("\"");
    }
    printf("]}\n");
    fflush(stdout);
}

static const char *argument_value(int argc, char **argv, const char *name) {
    int index;
    for (index = 1; index + 1 < argc; index++) {
        if (strcmp(argv[index], name) == 0) return argv[index + 1];
    }
    return NULL;
}

static int entry_name_matches(const char *symbol, const char *requested) {
    if (strcmp(symbol, requested) == 0) return 1;
#ifdef BOFBENCH_X86
    {
        char decorated[MAX_SYMBOL_NAME + 8];
        if (snprintf(decorated, sizeof(decorated), "_%s", requested) > 0 && strcmp(symbol, decorated) == 0) return 1;
        if (snprintf(decorated, sizeof(decorated), "_%s@8", requested) > 0 && strcmp(symbol, decorated) == 0) return 1;
    }
#endif
    return 0;
}

int main(int argc, char **argv) {
    const char *object = argument_value(argc, argv, "--object");
    const char *entry = argument_value(argc, argv, "--entry");
    const char *arg_hex = argument_value(argc, argv, "--arg-hex");
    size_t file_size = 0;
    uint8_t *file_base;
    coff_view view;
    uint8_t *image;
    uint8_t **section_bases;
    uint8_t *cursor;
    resolved_symbol resolved[MAX_RESOLVED_SYMBOLS] = {0};
    int resolved_count = 0;
    unsigned char *args;
    int args_len = 0;
    uintptr_t entry_address = 0;
    uint32_t entry_matches = 0;
    int entry_nonexecutable = 0;
    uint32_t section_index;
    uint32_t symbol_index;

    if (!object) object = "";
    if (!entry) entry = "go";
    if (!arg_hex) arg_hex = "";
    if (strlen(entry) > MAX_SYMBOL_NAME) {
        add_error("entry_name_limit", "entrypoint name exceeds the %u-byte loader limit", MAX_SYMBOL_NAME);
        print_json(object, entry, "fail", "arg_error");
        return 1;
    }
    file_base = (uint8_t *)read_file(object, &file_size);
    if (!file_base) {
        print_json(object, entry, "fail", strcmp(g_error_code, "oom") == 0 ? "oom" : "read_error");
        return 1;
    }
    if (file_size < sizeof(coff_file_header)) {
        add_error("header_range", "file is too small for a COFF header");
        print_json(object, entry, "fail", "validation_error");
        return 1;
    }
    if (((coff_file_header *)file_base)->machine != MACHINE_LOADER) {
        add_error("unsupported_machine", "unsupported machine 0x%04x; expected %s", ((coff_file_header *)file_base)->machine, LOADER_MACHINE_NAME);
        print_json(object, entry, "fail", "bad_arch");
        return 1;
    }
    if (((coff_file_header *)file_base)->size_of_optional_header != 0) {
        add_error("optional_header", "COFF object declares an unexpected %u-byte optional header", ((coff_file_header *)file_base)->size_of_optional_header);
        print_json(object, entry, "fail", "bad_object");
        return 1;
    }
    if (!validate_coff(file_base, file_size, &view)) {
        print_json(object, entry, "fail", strcmp(g_error_code, "oom") == 0 ? "oom" : "validation_error");
        return 1;
    }
    args = decode_hex(arg_hex, &args_len);
    if (!args) {
        print_json(object, entry, "fail", strcmp(g_error_code, "oom") == 0 ? "oom" : "arg_error");
        return 1;
    }
    section_bases = (uint8_t **)calloc(view.header->number_of_sections, sizeof(uint8_t *));
    if (!section_bases) {
        add_error("oom", "could not allocate mapped-section table");
        print_json(object, entry, "fail", "oom");
        return 1;
    }
    image = (uint8_t *)VirtualAlloc(NULL, view.image_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!image) {
        add_error("virtual_alloc", "VirtualAlloc failed: %lu", GetLastError());
        print_json(object, entry, "fail", "alloc_error");
        return 1;
    }
    cursor = image;
    for (section_index = 0; section_index < view.header->number_of_sections; section_index++) {
        coff_section_header *section = &view.sections[section_index];
        size_t aligned_size;
        section_bases[section_index] = cursor;
        if (section->size_of_raw_data > 0 && !(section->characteristics & SECTION_CNT_UNINITIALIZED_DATA)) {
            memcpy(cursor, view.file_base + section->pointer_to_raw_data, section->size_of_raw_data);
        }
        size_t allocation_size = view.section_sizes[section_index] ? view.section_sizes[section_index] : 1;
        if (!align_page(allocation_size, &aligned_size)) {
            add_error("image_size_overflow", "section alignment overflow after validation");
            print_json(object, entry, "fail", "validation_error");
            return 1;
        }
        cursor += aligned_size;
    }
    g_stub_cursor = image + view.section_image_size;
    g_stub_end = image + view.image_size;
    if (!apply_relocations(&view, image, section_bases, resolved, &resolved_count)) {
        print_json(object, entry, "fail", "relocation_error");
        return 1;
    }
    for (symbol_index = 0; symbol_index < view.header->number_of_symbols;) {
        coff_symbol *symbol = &view.symbols[symbol_index];
        char name[MAX_SYMBOL_NAME + 1];
        uint32_t next = symbol_index + 1u + symbol->number_of_aux_symbols;
        if (!copy_symbol_name(symbol, view.string_table, view.string_table_size, name, sizeof(name))) {
            print_json(object, entry, "fail", "validation_error");
            return 1;
        }
        if (entry_name_matches(name, entry)) {
            entry_matches++;
            if (symbol->section_number > 0 && symbol->section_number <= (int16_t)view.header->number_of_sections && symbol->value < view.section_sizes[symbol->section_number - 1]) {
                if (!(view.sections[symbol->section_number - 1].characteristics & SECTION_MEM_EXECUTE)) {
                    entry_nonexecutable = 1;
                } else {
                    entry_address = symbol_address(&view, symbol_index, section_bases, resolved, &resolved_count);
                }
            }
        }
        symbol_index = next;
    }
    if (entry_matches > 1) {
        add_error("entrypoint_ambiguous", "entrypoint %s resolves to %u symbols", entry, entry_matches);
        print_json(object, entry, "fail", "entry_ambiguous");
        return 1;
    }
    if (entry_nonexecutable) {
        add_error("entrypoint_section_nonexec", "entrypoint %s belongs to a non-executable section", entry);
        print_json(object, entry, "fail", "entry_invalid");
        return 1;
    }
    if (!entry_address) {
        add_error("entrypoint_missing", "entrypoint not found or not executable: %s", entry);
        print_json(object, entry, "fail", "entry_missing");
        return 1;
    }
    if (!protect_image(&view, image, section_bases)) {
        print_json(object, entry, "fail", "protect_error");
        return 1;
    }
    if (!FlushInstructionCache(GetCurrentProcess(), image, view.image_size)) {
        add_error("instruction_cache", "FlushInstructionCache failed: %lu", GetLastError());
        print_json(object, entry, "fail", "loader_error");
        return 1;
    }
    print_memory_event();
    {
        typedef void (*bof_entry)(char *, int);
        ((bof_entry)entry_address)((char *)args, args_len);
    }
    print_json(object, entry, "pass", "success");
    return 0;
}
