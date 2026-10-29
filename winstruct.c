/* Windows x64 PEB loader inspector - MinGW-w64 GCC */
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <wchar.h>
#include <inttypes.h>

#if !defined(_WIN64) || !defined(__x86_64__)
#error This example requires Windows x64 (MinGW-w64 x86_64).
#endif

/* Original function-pointer declarations, retained for future experiments. */
typedef int (WSAAPI *f_WSAStartup)(WORD, LPWSADATA);
typedef SOCKET (WSAAPI *f_WSASocketA)(int,int,int,LPWSAPROTOCOL_INFOA,GROUP,DWORD);
typedef struct hostent *(WSAAPI *f_gethostbyname)(const char *);
typedef char *(WSAAPI *f_inet_ntoa)(struct in_addr);
typedef u_short (WSAAPI *f_htons)(u_short);
typedef unsigned long (WSAAPI *f_inet_addr)(const char *);
typedef int (WSAAPI *f_WSAConnect)(SOCKET,SOCKADDR *,int,LPWSABUF,LPWSABUF,LPQOS,LPQOS);
typedef BOOL (WINAPI *f_CreateProcessA)(LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION);
typedef HMODULE (WINAPI *f_loadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI *f_GetProcAddress)(HMODULE,LPCSTR);

#define HEX_BYTES 32
#define TEXT_BYTES 30
#define ASM_BYTES 64
#define MAX_ASM_INSNS 10
#define MAX_MODULES 1024
#define MAX_EXPORTS 1048576

/* Windows x64 offsets: implementation-specific, not public ABI guarantees. */
#define TEB_PEB          0x60
#define PEB_LDR          0x18
#define LDR_MEMORY_LIST  0x20
#define ENTRY_LINKS      0x10
#define ENTRY_DLLBASE    0x30
#define ENTRY_FULLNAME   0x48
#define UNICODE_LENGTH   0x00
#define UNICODE_MAXLEN   0x02
#define UNICODE_BUFFER   0x08

static int opt_hex, opt_asm, opt_desc, opt_code, opt_code_full, opt_text;
static HANDLE con;
static WORD normal_attr = 7;

static void yellow(void) {
    if (con != INVALID_HANDLE_VALUE)
        SetConsoleTextAttribute(con, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
}
static void normal(void) {
    if (con != INVALID_HANDLE_VALUE) SetConsoleTextAttribute(con, normal_attr);
}
static void code_color(WORD foreground) {
    if (con != INVALID_HANDLE_VALUE)
        SetConsoleTextAttribute(con,(normal_attr & 0xfff0) | foreground);
}
static int c_keyword(const char *s, size_t n) {
    static const char *words[]={
        "break","case","char","const","continue","default","do","else","enum",
        "extern","for","if","int","long","return","short","signed","sizeof",
        "static","struct","switch","typedef","union","unsigned","void","volatile",
        "while","size_t","uint16_t","uint32_t","uint64_t","uintptr_t"
    };
    for (size_t i=0;i<sizeof(words)/sizeof(words[0]);i++)
        if (strlen(words[i])==n && !memcmp(s,words[i],n)) return 1;
    return 0;
}
static void code_span(const char *s, size_t n, WORD color) {
    code_color(color);
    fwrite(s,1,n,stdout);
    normal();
}
static void print_c_highlight(const char *s) {
    const WORD cyan=FOREGROUND_GREEN|FOREGROUND_BLUE|FOREGROUND_INTENSITY;
    const WORD green=FOREGROUND_GREEN|FOREGROUND_INTENSITY;
    const WORD magenta=FOREGROUND_RED|FOREGROUND_BLUE|FOREGROUND_INTENSITY;
    const WORD comment=FOREGROUND_GREEN;
    size_t i=0;
    while (s && s[i]) {
        if (s[i]=='/' && s[i+1]=='/') {
            size_t j=i+2; while (s[j] && s[j]!='\n') j++;
            code_span(s+i,j-i,comment); i=j; continue;
        }
        if (s[i]=='/' && s[i+1]=='*') {
            size_t j=i+2;
            while (s[j] && !(s[j]=='*' && s[j+1]=='/')) j++;
            if (s[j]) j+=2;
            code_span(s+i,j-i,comment); i=j; continue;
        }
        if (s[i]=='"' || s[i]=='\'') {
            char quote=s[i]; size_t j=i+1;
            while (s[j]) {
                if (s[j]=='\\' && s[j+1]) { j+=2; continue; }
                if (s[j++]==quote) break;
            }
            code_span(s+i,j-i,green); i=j; continue;
        }
        if (s[i]=='#' && (i==0 || s[i-1]=='\n')) {
            size_t j=i+1; while (s[j] && s[j]!='\n') j++;
            code_span(s+i,j-i,cyan); i=j; continue;
        }
        if ((s[i]>='0' && s[i]<='9')) {
            size_t j=i+1;
            while ((s[j]>='0' && s[j]<='9') || (s[j]>='a' && s[j]<='f') ||
                   (s[j]>='A' && s[j]<='F') || s[j]=='x' || s[j]=='X' || s[j]=='u' || s[j]=='U') j++;
            code_span(s+i,j-i,magenta); i=j; continue;
        }
        if ((s[i]>='A' && s[i]<='Z') || (s[i]>='a' && s[i]<='z') || s[i]=='_') {
            size_t j=i+1;
            while ((s[j]>='A' && s[j]<='Z') || (s[j]>='a' && s[j]<='z') ||
                   (s[j]>='0' && s[j]<='9') || s[j]=='_') j++;
            if (c_keyword(s+i,j-i)) code_span(s+i,j-i,cyan);
            else fwrite(s+i,1,j-i,stdout);
            i=j; continue;
        }
        putchar((unsigned char)s[i++]);
    }
    normal();
}
static void cputs(const char *s) {
    print_c_highlight(s);
    putchar('\n');
}
static void usage(const char *exe) {
    printf("Usage: %s [--func DLL:Function] [--hex] [--text] [--asm] [--desc] [--code|--code-full] [--help]\n", exe);
    puts("  --func DLL:Function  Resolve a named export and display every PE structure used");
    puts("  --hex   Show 32 bytes at each pointer destination");
    puts("  --text  Show 30 bytes as printable ASCII; non-printable bytes become '.'");
    puts("  --asm   Decode up to 10 instructions / 64 bytes at executable addresses");
    puts("  --desc  Explain fields");
    puts("  --code  Show standalone pointer-arithmetic C snippets (Windows x64 offsets)");
    puts("  --code-full  Show full PEB-to-data C code below each section (exclusive with --code)");
    puts("Flags can be combined; no flags = compact table.");
}

static void *teb_address(void) {
    void *result;
    __asm__ volatile ("movq %%gs:0x30, %0" : "=r" (result));
    return result;
}

static int readable(DWORD prot) {
    if (prot & (PAGE_GUARD | PAGE_NOACCESS)) return 0;
    switch (prot & 0xff) {
        case PAGE_READONLY: case PAGE_READWRITE: case PAGE_WRITECOPY:
        case PAGE_EXECUTE_READ: case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY: return 1;
        default: return 0;
    }
}
static int executable(DWORD prot) {
    if (prot & (PAGE_GUARD | PAGE_NOACCESS)) return 0;
    switch (prot & 0xff) {
        case PAGE_EXECUTE: case PAGE_EXECUTE_READ: case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY: return 1;
        default: return 0;
    }
}
static SIZE_T read_at(uintptr_t address, void *dst, SIZE_T length) {
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T got = 0;
    if (!address || !dst || !length || !VirtualQuery((const void *)address, &mbi, sizeof(mbi))) return 0;
    if (mbi.State != MEM_COMMIT || !readable(mbi.Protect)) return 0;
    uintptr_t start = (uintptr_t)mbi.BaseAddress;
    if (address < start || address - start >= mbi.RegionSize) return 0;
    SIZE_T available = mbi.RegionSize - (SIZE_T)(address - start);
    if (length > available) length = available;
    if (!ReadProcessMemory(GetCurrentProcess(), (const void *)address, dst, length, &got)) return got;
    return got;
}
static int read_ptr(uintptr_t address, uintptr_t *out) {
    return read_at(address, out, sizeof(*out)) == sizeof(*out);
}
static int read_u16(uintptr_t address, uint16_t *out) {
    return read_at(address, out, sizeof(*out)) == sizeof(*out);
}
static int is_exec_address(uintptr_t address) {
    MEMORY_BASIC_INFORMATION mbi;
    return address && VirtualQuery((void *)address, &mbi, sizeof(mbi)) &&
           mbi.State == MEM_COMMIT && executable(mbi.Protect);
}

static int32_t signed32(const unsigned char *p) {
    uint32_t v = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                 ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    return (int32_t)v;
}
static const char *reg64[] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                              "r8","r9","r10","r11","r12","r13","r14","r15"};
/* Deliberately small decoder. Returns 0 for unsupported/incomplete encodings. */
static size_t decode(const unsigned char *p, size_t n, uintptr_t pc, char *out, size_t cap) {
    if (!n) return 0;
    if (n >= 4 && p[0]==0xf3 && p[1]==0x0f && p[2]==0x1e && p[3]==0xfa) {
        snprintf(out, cap, "endbr64"); return 4;
    }
    switch (p[0]) {
        case 0x90: snprintf(out,cap,"nop"); return 1;
        case 0xc3: snprintf(out,cap,"ret"); return 1;
        case 0xcc: snprintf(out,cap,"int3"); return 1;
        case 0xc9: snprintf(out,cap,"leave"); return 1;
        case 0xfc: snprintf(out,cap,"cld"); return 1;
    }
    if (p[0]>=0x50 && p[0]<=0x57) { snprintf(out,cap,"push %s",reg64[p[0]-0x50]); return 1; }
    if (p[0]>=0x58 && p[0]<=0x5f) { snprintf(out,cap,"pop %s",reg64[p[0]-0x58]); return 1; }
    if (n>=2 && p[0]==0x41 && p[1]>=0x50 && p[1]<=0x57) {
        snprintf(out,cap,"push %s",reg64[8+p[1]-0x50]); return 2;
    }
    if (n>=2 && p[0]==0x41 && p[1]>=0x58 && p[1]<=0x5f) {
        snprintf(out,cap,"pop %s",reg64[8+p[1]-0x58]); return 2;
    }
    if (n>=5 && (p[0]==0xe8 || p[0]==0xe9)) {
        snprintf(out,cap,"%s 0x%" PRIXPTR,p[0]==0xe8?"call":"jmp", (uintptr_t)(pc+5+(int64_t)signed32(p+1)));
        return 5;
    }
    if (n>=2 && (p[0]==0xeb || p[0]==0x74 || p[0]==0x75)) {
        snprintf(out,cap,"%s 0x%" PRIXPTR,p[0]==0xeb?"jmp":p[0]==0x74?"jz":"jnz",
                 (uintptr_t)(pc+2+(int8_t)p[1])); return 2;
    }
    if (n>=5 && p[0]==0xb8) {
        snprintf(out,cap,"mov eax, 0x%X",(uint32_t)signed32(p+1)); return 5;
    }
    if (n>=3 && p[0]==0x48) {
        if (n>=5 && p[1]==0x89 && p[2]==0x5c && p[3]==0x24) {
            snprintf(out,cap,"mov qword ptr [rsp%+d], rbx",(int)(int8_t)p[4]); return 5;
        }
        if (n>=4 && p[1]==0x83 && (p[2]==0xec || p[2]==0xc4)) {
            snprintf(out,cap,"%s rsp, 0x%02X",p[2]==0xec?"sub":"add",p[3]); return 4;
        }
        if (n>=7 && p[1]==0x81 && (p[2]==0xec || p[2]==0xc4)) {
            snprintf(out,cap,"%s rsp, 0x%X",p[2]==0xec?"sub":"add",(uint32_t)signed32(p+3)); return 7;
        }
        if ((p[1]==0x89 || p[1]==0x8b || p[1]==0x31 || p[1]==0x33) && (p[2]&0xc0)==0xc0) {
            unsigned r=(p[2]>>3)&7, m=p[2]&7;
            int reverse=(p[1]==0x8b || p[1]==0x33);
            snprintf(out,cap,"%s %s, %s",(p[1]==0x31 || p[1]==0x33)?"xor":"mov",
                     reg64[reverse?r:m],reg64[reverse?m:r]); return 3;
        }
    }
    return 0;
}
static void dump_asm(uintptr_t address) {
    if (!is_exec_address(address)) return;
    unsigned char b[ASM_BYTES];
    SIZE_T n=read_at(address,b,sizeof(b));
    printf("           |      ASM  -> executable page (partial decoder)\n");
    if (!n) { puts("           |              [memory not readable]"); return; }
    size_t offset=0, count=0;
    while (offset<n && count<MAX_ASM_INSNS) {
        char dis[128];
        size_t used=decode(b+offset,n-offset,address+offset,dis,sizeof(dis));
        if (!used) {
            printf("           |              +0x%02zX  [unsupported/incomplete: %02X]\n", offset,b[offset]);
            break;
        }
        printf("           |              0x%016" PRIXPTR "  %s\n",address+offset,dis);
        offset+=used;
        count++;
    }
}
/* Columns are printed as one logical record; every optional column wraps
 * within its own fixed-width cell. No separate CODE/HEX pseudo-rows. */
#define DESC_COL_WIDTH 44
#define CODE_COL_WIDTH  58
#define HEX_COL_WIDTH   47 /* 16 bytes as "AA BB ..." */
#define TEXT_COL_WIDTH  TEXT_BYTES

static size_t text_line(const char *src, size_t pos, char *out, size_t width) {
    size_t len = src ? strlen(src) : 0;
    if (pos >= len) { out[0] = '\0'; return len; }
    while (pos < len && src[pos] == ' ') pos++;
    size_t end = pos + width;
    if (end > len) end = len;
    if (end < len) {
        size_t boundary = end;
        while (boundary > pos && src[boundary] != ' ') boundary--;
        if (boundary > pos) end = boundary;
    }
    size_t n = end - pos;
    memcpy(out, src + pos, n);
    out[n] = '\0';
    while (n && out[n-1] == ' ') out[--n] = '\0';
    while (end < len && src[end] == ' ') end++;
    return end;
}

static void hex_string(uintptr_t address, char *out, size_t cap) {
    unsigned char bytes[HEX_BYTES];
    SIZE_T n = read_at(address, bytes, sizeof bytes);
    if (!n) { snprintf(out, cap, "[unreadable]"); return; }
    size_t used = 0;
    for (SIZE_T i=0; i<n; i++) {
        int written = snprintf(out+used, cap-used, "%02X%s", bytes[i],
                               i+1<n ? ((i+1)%16==0 ? "\n" : " ") : "");
        if (written < 0 || (size_t)written >= cap-used) break;
        used += (size_t)written;
    }
    if (n < HEX_BYTES && used < cap) snprintf(out+used, cap-used, "\n[partial: %llu/%d bytes]",
                                           (unsigned long long)n, HEX_BYTES);
}

static size_t hex_line(const char *hex, size_t pos, char out[HEX_COL_WIDTH+1]) {
    size_t len = strlen(hex);
    if (pos >= len) { out[0] = '\0'; return len; }
    size_t end = pos;
    while (end < len && hex[end] != '\n' && end-pos < HEX_COL_WIDTH) end++;
    size_t n = end-pos;
    memcpy(out, hex+pos, n); out[n] = '\0';
    return hex[end] == '\n' ? end+1 : end;
}

static void text_string(uintptr_t address, char out[TEXT_BYTES+1]) {
    unsigned char bytes[TEXT_BYTES];
    SIZE_T n=read_at(address,bytes,sizeof bytes);
    if (!n) {
        snprintf(out,TEXT_BYTES+1,"[unreadable]");
        return;
    }
    for (SIZE_T i=0;i<n;i++) out[i]=(bytes[i]>=0x20 && bytes[i]<=0x7e) ? (char)bytes[i] : '.';
    out[n]='\0';
}

static void header(const char *name, uintptr_t base) {
    puts("\n----------------------------------------------------------------------------------------------");
    printf(" STRUCTURE: %s | BASE: ", name);
    yellow(); printf("0x%016" PRIXPTR, base); normal(); putchar('\n');
    printf(" %-8s | %-18s | %-29s | %-18s", "OFFSET", "ADDRESS", "FIELD", "VALUE");
    if (opt_desc) printf(" | %-*s", DESC_COL_WIDTH, "DESCRIPTION");
    if (opt_code) printf(" | %-*s", CODE_COL_WIDTH, "CODE (C / OFFSETS)");
    if (opt_hex)  printf(" | %-*s", HEX_COL_WIDTH, "HEX [32] AT VALUE");
    if (opt_text) printf(" | %-*s", TEXT_COL_WIDTH, "ASCII [30] AT VALUE");
    putchar('\n');
    puts("----------------------------------------------------------------------------------------------");
}

static void row(uintptr_t parent, size_t off, const char *name,
                uintptr_t value, int is_number, unsigned number,
                const char *desc, const char *code) {
    char hex[160] = "";
    char ascii[TEXT_BYTES+1] = "";
    if (opt_hex && !is_number) hex_string(value, hex, sizeof hex);
    if (opt_text && !is_number) text_string(value,ascii);
    size_t dpos=0, cpos=0, hpos=0;
    int first = 1;
    do {
        char dline[DESC_COL_WIDTH+1] = "";
        char cline[CODE_COL_WIDTH+1] = "";
        char hline[HEX_COL_WIDTH+1] = "";
        if (opt_desc) dpos=text_line(desc, dpos, dline, DESC_COL_WIDTH);
        if (opt_code) cpos=text_line(code, cpos, cline, CODE_COL_WIDTH);
        if (opt_hex) hpos=hex_line(hex, hpos, hline);
        if (first) {
            printf(" +0x%04zX  | 0x%016" PRIXPTR " | %-29s | ", off, parent+off, name);
            if (is_number==1) printf("%-18u", number);
            else if (is_number==2) printf("0x%-16X", number);
            else { yellow(); printf("0x%016" PRIXPTR, value); normal(); }
        } else {
            printf(" %-8s | %-18s | %-29s | %-18s", "", "", "", "");
        }
        if (opt_desc) printf(" | %-*s", DESC_COL_WIDTH, dline);
        if (opt_code) {
            printf(" | ");
            print_c_highlight(cline);
            printf("%*s",CODE_COL_WIDTH-(int)strlen(cline),"");
        }
        if (opt_hex) printf(" | %-*s", HEX_COL_WIDTH, hline);
        if (opt_text) printf(" | %-*s", TEXT_COL_WIDTH, first ? ascii : "");
        putchar('\n');
        first=0;
    } while ((opt_desc && desc && dpos < strlen(desc)) ||
             (opt_code && code && cpos < strlen(code)) ||
             (opt_hex && hpos < strlen(hex)));
    if (!first && (opt_desc || opt_hex || opt_code || opt_text)) putchar('\n');
    if (opt_asm && !is_number) dump_asm(value);
}

static void pointer_field(uintptr_t parent, size_t off, const char *name,
                          uintptr_t value, const char *desc, const char *code) {
    row(parent, off, name, value, 0, 0, desc, code);
}
static void number_field(uintptr_t parent, size_t off, const char *name,
                         unsigned number, const char *desc, const char *code) {
    row(parent, off, name, 0, 1, number, desc, code);
}
static void hex_number_field(uintptr_t parent, size_t off, const char *name,
                             unsigned number, const char *desc, const char *code) {
    row(parent, off, name, 0, 2, number, desc, code);
}
static int is_module_name(uintptr_t buffer, unsigned byte_len, const char *wanted) {
    if (!buffer || byte_len == 0 || (byte_len % 2) || byte_len > 32768) return 0;
    wchar_t str[16385];
    if (read_at(buffer,str,byte_len)!=byte_len) return 0;
    size_t n=byte_len/sizeof(wchar_t), start=0;
    for (size_t i=0;i<n;i++) if (str[i]==L'\\' || str[i]==L'/') start=i+1;
    size_t t=strlen(wanted);
    if (n-start != t) return 0;
    for (size_t i=0;i<t;i++) {
        wchar_t a=str[start+i];
        unsigned char b=(unsigned char)wanted[i];
        if (a>=L'A' && a<=L'Z') a+=(L'a'-L'A');
        if (b>='A' && b<='Z') b=(unsigned char)(b+('a'-'A'));
        if (a!=b) return 0;
    }
    return 1;
}
static void print_name(uintptr_t buffer, unsigned len) {
    wchar_t str[16385];
    printf("           |      DLL  -> ");
    if (!buffer || len>32768 || (len%2) || read_at(buffer,str,len)!=len) {
        puts("[unavailable]"); return;
    }
    str[len/sizeof(wchar_t)]=0;
    yellow(); printf("%.*ls",(int)(len/sizeof(wchar_t)),str); normal(); putchar('\n');
}

enum full_code_section {
    FULL_TEB, FULL_PEB, FULL_LDR, FULL_LDR_ENTRY, FULL_DOS,
    FULL_NT, FULL_EXPORT_DATA, FULL_EXPORT_DIR, FULL_EXPORT_LOOKUP
};

static void full_code_begin(const char *path) {
    if (!opt_code_full) return;
    puts("\n  FULL C CODE (hardcoded Windows x64 offsets)");
    printf("  PATH: %s\n",path);
    puts("  --------------------------------------------------------------------------");
    cputs("#include <stdint.h>");
    cputs("#include <stddef.h>");
    cputs("#include <string.h>");
}

static void full_code_request_comment(const char *module, const char *function) {
    char line[1600];
    if (!module) return;
    if (function) snprintf(line,sizeof line,"/* Requested export: %s:%s */",module,function);
    else snprintf(line,sizeof line,"/* Requested module: %s */",module);
    cputs(line);
}

static void full_module_lookup(void) {
    cputs(
"\nstatic int same_module_name(uintptr_t entry, const char *wanted) {\n"
"    uint16_t bytes = *(uint16_t *)(entry + 0x48);\n"
"    uintptr_t buffer = *(uintptr_t *)(entry + 0x50);\n"
"    size_t count = bytes / 2, start = 0, wanted_len = strlen(wanted);\n"
"    uint16_t *name = (uint16_t *)buffer;\n"
"    for (size_t i = 0; i < count; ++i)\n"
"        if (name[i] == '\\\\' || name[i] == '/') start = i + 1;\n"
"    if (count - start != wanted_len) return 0;\n"
"    for (size_t i = 0; i < wanted_len; ++i) {\n"
"        uint16_t a = name[start + i];\n"
"        unsigned char b = (unsigned char)wanted[i];\n"
"        if (a >= 'A' && a <= 'Z') a += 'a' - 'A';\n"
"        if (b >= 'A' && b <= 'Z') b += 'a' - 'A';\n"
"        if (a != b) return 0;\n"
"    }\n"
"    return 1;\n"
"}\n"
"\nstatic uintptr_t find_module_entry(uintptr_t peb, const char *wanted) {\n"
"    uintptr_t ldr = *(uintptr_t *)(peb + 0x18);\n"
"    uintptr_t head = ldr + 0x20;\n"
"    uintptr_t curr = *(uintptr_t *)(head + 0x00);\n"
"    for (unsigned n = 0; curr && curr != head && n < 1024; ++n) {\n"
"        uintptr_t entry = curr - 0x10;\n"
"        if (same_module_name(entry, wanted)) return entry;\n"
"        curr = *(uintptr_t *)(curr + 0x00);\n"
"    }\n"
"    return 0;\n"
"}\n"
"\nstatic uintptr_t find_module_base(uintptr_t peb, const char *wanted) {\n"
"    uintptr_t entry = find_module_entry(peb, wanted);\n"
"    return entry ? *(uintptr_t *)(entry + 0x30) : 0;\n"
"}");
}

static void print_full_code(enum full_code_section section,
                            const char *module_name, const char *function_name) {
    if (!opt_code_full) return;
    switch (section) {
        case FULL_TEB:
            full_code_begin("CPU GS -> TEB -> PEB pointer");
            cputs(
"\nstatic uintptr_t get_peb_from_teb(void) {\n"
"    uintptr_t teb;\n"
"    __asm__ volatile (\"movq %%gs:0x30, %0\" : \"=r\"(teb));\n"
"    return *(uintptr_t *)(teb + 0x60);\n"
"}");
            break;
        case FULL_PEB:
            full_code_begin("CPU GS -> PEB");
            cputs(
"\nstatic uintptr_t get_current_peb(void) {\n"
"    uintptr_t peb;\n"
"    __asm__ volatile (\"movq %%gs:0x60, %0\" : \"=r\"(peb));\n"
"    uintptr_t ldr = *(uintptr_t *)(peb + 0x18);\n"
"    (void)ldr;\n"
"    return peb;\n"
"}");
            break;
        case FULL_LDR:
            full_code_begin("PEB -> PEB_LDR_DATA -> InMemoryOrderModuleList");
            cputs(
"\nstatic void reach_loader_list(uintptr_t peb) {\n"
"    uintptr_t ldr = *(uintptr_t *)(peb + 0x18);\n"
"    uintptr_t head = ldr + 0x20;\n"
"    uintptr_t first = *(uintptr_t *)(head + 0x00);\n"
"    uintptr_t last = *(uintptr_t *)(head + 0x08);\n"
"    (void)first; (void)last;\n"
"}");
            break;
        case FULL_LDR_ENTRY:
            full_code_begin("PEB -> matching LDR_DATA_TABLE_ENTRY");
            full_code_request_comment(module_name,NULL);
            full_module_lookup();
            cputs(
"\nstatic void inspect_module_entry(uintptr_t peb, const char *module) {\n"
"    uintptr_t entry = find_module_entry(peb, module);\n"
"    if (!entry) return;\n"
"    uintptr_t links = entry + 0x10;\n"
"    uintptr_t next = *(uintptr_t *)(entry + 0x10);\n"
"    uintptr_t previous = *(uintptr_t *)(entry + 0x18);\n"
"    uintptr_t dll_base = *(uintptr_t *)(entry + 0x30);\n"
"    uint16_t name_bytes = *(uint16_t *)(entry + 0x48);\n"
"    uint16_t name_capacity = *(uint16_t *)(entry + 0x4A);\n"
"    uintptr_t name_buffer = *(uintptr_t *)(entry + 0x50);\n"
"    (void)links; (void)next; (void)previous; (void)dll_base;\n"
"    (void)name_bytes; (void)name_capacity; (void)name_buffer;\n"
"}");
            break;
        case FULL_DOS:
            full_code_begin("PEB -> module base -> IMAGE_DOS_HEADER data");
            full_code_request_comment(module_name,NULL);
            full_module_lookup();
            cputs(
"\nstatic uintptr_t reach_nt_headers(uintptr_t peb, const char *module) {\n"
"    uintptr_t base = find_module_base(peb, module);\n"
"    if (!base || *(uint16_t *)(base + 0x00) != 0x5A4D) return 0;\n"
"    uint32_t e_lfanew = *(uint32_t *)(base + 0x3C);\n"
"    return base + e_lfanew;\n"
"}");
            break;
        case FULL_NT:
            full_code_begin("PEB -> module base -> IMAGE_NT_HEADERS64 data");
            full_code_request_comment(module_name,NULL);
            full_module_lookup();
            cputs(
"\nstatic void inspect_nt_headers(uintptr_t peb, const char *module) {\n"
"    uintptr_t base = find_module_base(peb, module);\n"
"    if (!base || *(uint16_t *)(base + 0x00) != 0x5A4D) return;\n"
"    uintptr_t nt = base + *(uint32_t *)(base + 0x3C);\n"
"    uint32_t signature = *(uint32_t *)(nt + 0x00);\n"
"    uint16_t machine = *(uint16_t *)(nt + 0x04);\n"
"    uint16_t sections = *(uint16_t *)(nt + 0x06);\n"
"    uint16_t optional_size = *(uint16_t *)(nt + 0x14);\n"
"    uint16_t magic = *(uint16_t *)(nt + 0x18);\n"
"    uint32_t entry_rva = *(uint32_t *)(nt + 0x28);\n"
"    uintptr_t entry_va = base + entry_rva;\n"
"    uint64_t preferred_base = *(uint64_t *)(nt + 0x30);\n"
"    uint32_t image_size = *(uint32_t *)(nt + 0x50);\n"
"    uint32_t directory_count = *(uint32_t *)(nt + 0x84);\n"
"    (void)signature; (void)machine; (void)sections; (void)optional_size;\n"
"    (void)magic; (void)entry_va; (void)preferred_base;\n"
"    (void)image_size; (void)directory_count;\n"
"}");
            break;
        case FULL_EXPORT_DATA:
            full_code_begin("PEB -> module base -> export IMAGE_DATA_DIRECTORY");
            full_code_request_comment(module_name,NULL);
            full_module_lookup();
            cputs(
"\nstatic uintptr_t reach_export_directory(uintptr_t peb, const char *module) {\n"
"    uintptr_t base = find_module_base(peb, module);\n"
"    if (!base) return 0;\n"
"    uintptr_t nt = base + *(uint32_t *)(base + 0x3C);\n"
"    uint32_t export_rva = *(uint32_t *)(nt + 0x88);\n"
"    uint32_t export_size = *(uint32_t *)(nt + 0x8C);\n"
"    (void)export_size;\n"
"    return export_rva ? base + export_rva : 0;\n"
"}");
            break;
        case FULL_EXPORT_DIR:
            full_code_begin("PEB -> module base -> IMAGE_EXPORT_DIRECTORY data");
            full_code_request_comment(module_name,NULL);
            full_module_lookup();
            cputs(
"\nstatic void inspect_export_directory(uintptr_t peb, const char *module) {\n"
"    uintptr_t base = find_module_base(peb, module);\n"
"    if (!base) return;\n"
"    uintptr_t nt = base + *(uint32_t *)(base + 0x3C);\n"
"    uintptr_t exp = base + *(uint32_t *)(nt + 0x88);\n"
"    uint32_t flags = *(uint32_t *)(exp + 0x00);\n"
"    uint32_t stamp = *(uint32_t *)(exp + 0x04);\n"
"    uint16_t major = *(uint16_t *)(exp + 0x08);\n"
"    uint16_t minor = *(uint16_t *)(exp + 0x0A);\n"
"    char *dll_name = (char *)(base + *(uint32_t *)(exp + 0x0C));\n"
"    uint32_t ordinal_base = *(uint32_t *)(exp + 0x10);\n"
"    uint32_t function_count = *(uint32_t *)(exp + 0x14);\n"
"    uint32_t name_count = *(uint32_t *)(exp + 0x18);\n"
"    uint32_t *functions = (uint32_t *)(base + *(uint32_t *)(exp + 0x1C));\n"
"    uint32_t *names = (uint32_t *)(base + *(uint32_t *)(exp + 0x20));\n"
"    uint16_t *ordinals = (uint16_t *)(base + *(uint32_t *)(exp + 0x24));\n"
"    (void)flags; (void)stamp; (void)major; (void)minor; (void)dll_name;\n"
"    (void)ordinal_base; (void)function_count; (void)name_count;\n"
"    (void)functions; (void)names; (void)ordinals;\n"
"}");
            break;
        case FULL_EXPORT_LOOKUP:
            full_code_begin("PEB -> module base -> named export address");
            full_code_request_comment(module_name,function_name);
            full_module_lookup();
            cputs(
"\nstatic uintptr_t find_export_from_peb(uintptr_t peb, const char *module,\n"
"                                      const char *wanted) {\n"
"    uintptr_t base = find_module_base(peb, module);\n"
"    if (!base || *(uint16_t *)(base + 0x00) != 0x5A4D) return 0;\n"
"    uintptr_t nt = base + *(uint32_t *)(base + 0x3C);\n"
"    if (*(uint32_t *)(nt + 0x00) != 0x00004550) return 0;\n"
"    uint32_t export_rva = *(uint32_t *)(nt + 0x88);\n"
"    if (!export_rva) return 0;\n"
"    uintptr_t exp = base + export_rva;\n"
"    uint32_t function_count = *(uint32_t *)(exp + 0x14);\n"
"    uint32_t name_count = *(uint32_t *)(exp + 0x18);\n"
"    uintptr_t functions = base + *(uint32_t *)(exp + 0x1C);\n"
"    uintptr_t names = base + *(uint32_t *)(exp + 0x20);\n"
"    uintptr_t ordinals = base + *(uint32_t *)(exp + 0x24);\n"
"    for (uint32_t i = 0; i < name_count; ++i) {\n"
"        uint32_t name_rva = *(uint32_t *)(names + i * 4);\n"
"        char *name = (char *)(base + name_rva);\n"
"        if (strcmp(name, wanted) != 0) continue;\n"
"        uint16_t index = *(uint16_t *)(ordinals + i * 2);\n"
"        if (index >= function_count) return 0;\n"
"        uint32_t function_rva = *(uint32_t *)(functions + index * 4);\n"
"        return base + function_rva;\n"
"    }\n"
"    return 0;\n"
"}");
            break;
    }
    puts("  --------------------------------------------------------------------------");
}

static uintptr_t resolver(const char *module_name) {
    uintptr_t teb=(uintptr_t)teb_address(), peb=0, ldr=0;
    header("TEB",teb);
    pointer_field(teb,0,"[STRUCT BASE]",teb,
        "Beginning of thread environment block; not a real field.",
        "uintptr_t teb; __asm__ volatile(\"movq %%gs:0x30, %0\" : \"=r\"(teb));");
    if (!read_ptr(teb+TEB_PEB,&peb)) return 0;
    pointer_field(teb,TEB_PEB,"ProcessEnvironmentBlock",peb,
        "Pointer to the process environment block (PEB).",
        "uintptr_t peb = *(uintptr_t *)(teb + 0x60);");
    print_full_code(FULL_TEB,module_name,NULL);

    header("PEB",peb);
    pointer_field(peb,0,"[STRUCT BASE]",peb,
        "Beginning of process environment block; not a real field.",
        "uintptr_t peb = *(uintptr_t *)(teb + 0x60);");
    if (!read_ptr(peb+PEB_LDR,&ldr)) return 0;
    pointer_field(peb,PEB_LDR,"Ldr",ldr,
        "Points to loader data and module lists.",
        "uintptr_t ldr = *(uintptr_t *)(peb + 0x18);");
    print_full_code(FULL_PEB,module_name,NULL);

    uintptr_t head=ldr+LDR_MEMORY_LIST, curr=0, last=0;
    header("PEB_LDR_DATA",ldr);
    pointer_field(ldr,0,"[STRUCT BASE]",ldr,
        "Loader data block; not a real field.",
        "uintptr_t ldr = *(uintptr_t *)(peb + 0x18);");
    pointer_field(ldr,LDR_MEMORY_LIST,"InMemoryOrderModuleList",head,
        "Address of the circular list's sentinel, not a DLL entry.",
        "uintptr_t head = ldr + 0x20;");
    if (!read_ptr(head,&curr) || !read_ptr(head+8,&last)) return 0;
    pointer_field(head,0,"InMemoryOrderList.Flink",curr,
        "First LIST_ENTRY link (or the sentinel if empty).",
        "uintptr_t curr = *(uintptr_t *)(ldr + 0x20);");
    pointer_field(head,8,"InMemoryOrderList.Blink",last,
        "Last LIST_ENTRY link in the circular list.",
        "uintptr_t last = *(uintptr_t *)(ldr + 0x28);");
    print_full_code(FULL_LDR,module_name,NULL);

    for (unsigned idx=1;curr!=head && idx<=MAX_MODULES;idx++) {
        if (!curr || curr<ENTRY_LINKS) return 0;
        uintptr_t entry=curr-ENTRY_LINKS, next=0, prev=0, dll=0, namebuf=0;
        uint16_t len=0,maxlen=0;
        if (!read_ptr(curr,&next) || !read_ptr(curr+8,&prev) ||
            !read_ptr(entry+ENTRY_DLLBASE,&dll) ||
            !read_u16(entry+ENTRY_FULLNAME+UNICODE_LENGTH,&len) ||
            !read_u16(entry+ENTRY_FULLNAME+UNICODE_MAXLEN,&maxlen) ||
            !read_ptr(entry+ENTRY_FULLNAME+UNICODE_BUFFER,&namebuf)) return 0;
        printf("\n[MODULE %u]\n",idx);
        header("LDR_DATA_TABLE_ENTRY",entry);
        pointer_field(entry,0,"[STRUCT BASE]",entry,
            "Start of module descriptor; curr points 0x10 bytes into it.",
            "uintptr_t entry = curr - 0x10;");
        pointer_field(entry,ENTRY_LINKS,"InMemoryOrderLinks (curr)",curr,
            "Embedded list node inside the module descriptor.",
            "uintptr_t curr = entry + 0x10;");
        pointer_field(entry,ENTRY_LINKS,"InMemoryOrderLinks.Flink",next,
            "Next list node; stop when it equals head.",
            "uintptr_t next = *(uintptr_t *)(entry + 0x10);");
        pointer_field(entry,ENTRY_LINKS+8,"InMemoryOrderLinks.Blink",prev,
            "Previous list node.",
            "uintptr_t previous = *(uintptr_t *)(entry + 0x18);");
        pointer_field(entry,ENTRY_DLLBASE,"DllBase",dll,
            "Base address of the mapped PE image (usually begins with MZ).",
            "uintptr_t dllBase = *(uintptr_t *)(entry + 0x30);");
        number_field(entry,ENTRY_FULLNAME,"FullDllName.Length",len,
            "Valid UTF-16LE byte length, excluding NUL.",
            "uint16_t nameBytes = *(uint16_t *)(entry + 0x48);");
        number_field(entry,ENTRY_FULLNAME+2,"FullDllName.MaximumLength",maxlen,
            "Capacity of the Unicode buffer in bytes.",
            "uint16_t capacity = *(uint16_t *)(entry + 0x4A);");
        pointer_field(entry,ENTRY_FULLNAME+UNICODE_BUFFER,"FullDllName.Buffer",namebuf,
            "Pointer to a UTF-16LE full DLL path; may not be NUL-terminated.",
            "uintptr_t nameBuffer = *(uintptr_t *)(entry + 0x50);");
        print_name(namebuf,len);
        int module_matches=is_module_name(namebuf,len,module_name);
        if (module_matches) {
            print_full_code(FULL_LDR_ENTRY,module_name,NULL);
            printf("\n[+] %s FOUND: ",module_name);
            yellow(); printf("0x%016" PRIXPTR "\n",dll); normal();
            return dll;
        }
        curr=next;
    }
    puts("[!] Module not found or iteration limit reached.");
    return 0;
}

static int image_range(uint32_t rva, size_t length, uint32_t image_size) {
    return rva < image_size && length <= (size_t)(image_size-rva);
}

static int read_image_string(uintptr_t base, uint32_t rva, uint32_t image_size,
                             char *out, size_t capacity) {
    if (!out || capacity < 2 || !image_range(rva,1,image_size)) return 0;
    size_t limit=image_size-rva;
    if (limit>capacity-1) limit=capacity-1;
    for (size_t i=0;i<limit;i++) {
        if (read_at(base+rva+i,&out[i],1)!=1) return 0;
        if (!out[i]) return 1;
    }
    out[capacity-1]=0;
    return 0;
}

static uintptr_t explain_export(uintptr_t base, const char *module_name,
                                const char *function_name) {
    IMAGE_DOS_HEADER dos;
    if (read_at(base,&dos,sizeof dos)!=sizeof dos || dos.e_magic!=IMAGE_DOS_SIGNATURE) {
        puts("[!] The module does not contain a readable MZ/DOS header.");
        return 0;
    }
    if (dos.e_lfanew<=0 || dos.e_lfanew>0x100000) {
        puts("[!] Invalid e_lfanew in DOS header.");
        return 0;
    }

    uintptr_t nt_address=base+(uint32_t)dos.e_lfanew;
    IMAGE_NT_HEADERS64 nt;
    if (read_at(nt_address,&nt,sizeof nt)!=sizeof nt ||
        nt.Signature!=IMAGE_NT_SIGNATURE || nt.OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        puts("[!] Invalid or non-PE32+ NT headers.");
        return 0;
    }
    if (nt.FileHeader.SizeOfOptionalHeader <
        offsetof(IMAGE_OPTIONAL_HEADER64,DataDirectory)+sizeof(IMAGE_DATA_DIRECTORY)) {
        puts("[!] Optional header is too short to contain the export data-directory slot.");
        return 0;
    }
    uint32_t image_size=nt.OptionalHeader.SizeOfImage;
    if (!image_size || nt.OptionalHeader.NumberOfRvaAndSizes<=IMAGE_DIRECTORY_ENTRY_EXPORT) {
        puts("[!] The image has no export data-directory slot.");
        return 0;
    }

    header("IMAGE_DOS_HEADER",base);
    hex_number_field(base,offsetof(IMAGE_DOS_HEADER,e_magic),"e_magic (MZ)",dos.e_magic,
        "DOS signature 0x5A4D. It identifies the beginning of a PE image.",
        "uint16_t mz = *(uint16_t *)(base + 0x00);");
    hex_number_field(base,offsetof(IMAGE_DOS_HEADER,e_lfanew),"e_lfanew",(unsigned)dos.e_lfanew,
        "File/memory offset from the image base to IMAGE_NT_HEADERS64.",
        "uint32_t e_lfanew = *(uint32_t *)(base + 0x3C);");
    pointer_field(base,offsetof(IMAGE_DOS_HEADER,e_lfanew),"e_lfanew -> NT headers",nt_address,
        "Computed address (base + e_lfanew); this is explanatory, not a pointer field stored in the header.",
        "uintptr_t ntAddress = base + *(uint32_t *)(base + 0x3C);");
    print_full_code(FULL_DOS,module_name,NULL);

    header("IMAGE_NT_HEADERS64",nt_address);
    hex_number_field(nt_address,offsetof(IMAGE_NT_HEADERS64,Signature),"Signature (PE\\0\\0)",nt.Signature,
        "NT signature 0x00004550, checked before using the remaining fields.",
        "if (*(uint32_t *)(ntAddress + 0x00) != 0x00004550) return 0;");
    hex_number_field(nt_address,offsetof(IMAGE_NT_HEADERS64,FileHeader.Machine),"FileHeader.Machine",nt.FileHeader.Machine,
        "Target machine type; AMD64 is 0x8664.","uint16_t machine = *(uint16_t *)(ntAddress + 0x04);");
    number_field(nt_address,offsetof(IMAGE_NT_HEADERS64,FileHeader.NumberOfSections),"FileHeader.NumberOfSections",nt.FileHeader.NumberOfSections,
        "Number of PE section headers following the optional header.","uint16_t sections = *(uint16_t *)(ntAddress + 0x06);");
    number_field(nt_address,offsetof(IMAGE_NT_HEADERS64,FileHeader.SizeOfOptionalHeader),"FileHeader.SizeOfOptionalHeader",nt.FileHeader.SizeOfOptionalHeader,
        "Byte size of IMAGE_OPTIONAL_HEADER64 in this image.","uint16_t optionalBytes = *(uint16_t *)(ntAddress + 0x14);");
    hex_number_field(nt_address,offsetof(IMAGE_NT_HEADERS64,OptionalHeader.Magic),"OptionalHeader.Magic",nt.OptionalHeader.Magic,
        "PE32+ signature 0x20B, used by 64-bit images.","uint16_t magic = *(uint16_t *)(ntAddress + 0x18);");
    hex_number_field(nt_address,offsetof(IMAGE_NT_HEADERS64,OptionalHeader.AddressOfEntryPoint),"AddressOfEntryPoint (RVA)",nt.OptionalHeader.AddressOfEntryPoint,
        "RVA of the image entry point; it is relative to the mapped module base.","uint32_t entryRva = *(uint32_t *)(ntAddress + 0x28);");
    pointer_field(nt_address,offsetof(IMAGE_NT_HEADERS64,OptionalHeader.AddressOfEntryPoint),"AddressOfEntryPoint -> VA",base+nt.OptionalHeader.AddressOfEntryPoint,
        "Entry-point RVA converted to a process virtual address by adding the mapped image base.","uintptr_t entry = base + *(uint32_t *)(ntAddress + 0x28);");
    pointer_field(nt_address,offsetof(IMAGE_NT_HEADERS64,OptionalHeader.ImageBase),"OptionalHeader.ImageBase",(uintptr_t)nt.OptionalHeader.ImageBase,
        "Preferred image base recorded in the PE; ASLR may map the module elsewhere.","uint64_t preferred = *(uint64_t *)(ntAddress + 0x30);");
    number_field(nt_address,offsetof(IMAGE_NT_HEADERS64,OptionalHeader.SizeOfImage),"OptionalHeader.SizeOfImage",image_size,
        "Total mapped image size, used to bound every RVA dereference.","uint32_t imageSize = *(uint32_t *)(ntAddress + 0x50);");
    number_field(nt_address,offsetof(IMAGE_NT_HEADERS64,OptionalHeader.NumberOfRvaAndSizes),"NumberOfRvaAndSizes",nt.OptionalHeader.NumberOfRvaAndSizes,
        "Number of valid IMAGE_DATA_DIRECTORY elements.","uint32_t count = *(uint32_t *)(ntAddress + 0x84);");
    print_full_code(FULL_NT,module_name,NULL);

    IMAGE_DATA_DIRECTORY data=nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    uintptr_t data_address=nt_address+offsetof(IMAGE_NT_HEADERS64,OptionalHeader.DataDirectory)+
                           IMAGE_DIRECTORY_ENTRY_EXPORT*sizeof(IMAGE_DATA_DIRECTORY);
    header("IMAGE_DATA_DIRECTORY [EXPORT]",data_address);
    hex_number_field(data_address,offsetof(IMAGE_DATA_DIRECTORY,VirtualAddress),"VirtualAddress (RVA)",data.VirtualAddress,
        "Stored RVA of IMAGE_EXPORT_DIRECTORY.","uint32_t exportRva = *(uint32_t *)(ntAddress + 0x88);");
    pointer_field(data_address,offsetof(IMAGE_DATA_DIRECTORY,VirtualAddress),"VirtualAddress -> export VA",base+data.VirtualAddress,
        "RVA of IMAGE_EXPORT_DIRECTORY, converted to VA by adding the mapped module base.",
        "uintptr_t exportDir = base + *(uint32_t *)(ntAddress + 0x88);");
    number_field(data_address,offsetof(IMAGE_DATA_DIRECTORY,Size),"Size",data.Size,
        "Byte span of the export directory; function RVAs inside this span are forwarder strings.","uint32_t exportBytes = *(uint32_t *)(ntAddress + 0x8C);");
    print_full_code(FULL_EXPORT_DATA,module_name,NULL);
    if (!data.VirtualAddress || data.Size<sizeof(IMAGE_EXPORT_DIRECTORY) ||
        !image_range(data.VirtualAddress,data.Size,image_size)) {
        puts("[!] This module has no valid export directory.");
        return 0;
    }

    uintptr_t export_address=base+data.VirtualAddress;
    IMAGE_EXPORT_DIRECTORY exp;
    if (read_at(export_address,&exp,sizeof exp)!=sizeof exp) {
        puts("[!] Export directory is not readable."); return 0;
    }
    header("IMAGE_EXPORT_DIRECTORY",export_address);
    number_field(export_address,offsetof(IMAGE_EXPORT_DIRECTORY,Characteristics),"Characteristics",exp.Characteristics,
        "Reserved export-table flags; normally zero.","uint32_t flags = *(uint32_t *)(exportDir + 0x00);");
    hex_number_field(export_address,offsetof(IMAGE_EXPORT_DIRECTORY,TimeDateStamp),"TimeDateStamp",exp.TimeDateStamp,
        "Linker timestamp value stored by the image producer.","uint32_t stamp = *(uint32_t *)(exportDir + 0x04);");
    number_field(export_address,offsetof(IMAGE_EXPORT_DIRECTORY,MajorVersion),"MajorVersion",exp.MajorVersion,
        "Export table major version, commonly zero.","uint16_t major = *(uint16_t *)(exportDir + 0x08);");
    number_field(export_address,offsetof(IMAGE_EXPORT_DIRECTORY,MinorVersion),"MinorVersion",exp.MinorVersion,
        "Export table minor version, commonly zero.","uint16_t minor = *(uint16_t *)(exportDir + 0x0A);");
    hex_number_field(export_address,offsetof(IMAGE_EXPORT_DIRECTORY,Name),"Name (RVA)",exp.Name,
        "Stored RVA of the exporting module's ASCII name.","uint32_t dllNameRva = *(uint32_t *)(exportDir + 0x0C);");
    pointer_field(export_address,offsetof(IMAGE_EXPORT_DIRECTORY,Name),"Name RVA -> DLL name VA",base+exp.Name,
        "RVA of the ASCII name identifying the exporting module.","char *dllName = (char *)(base + *(uint32_t *)(exportDir + 0x0C));");
    number_field(export_address,offsetof(IMAGE_EXPORT_DIRECTORY,Base),"Base (ordinal bias)",exp.Base,
        "Bias added to a function-table index to form its public ordinal.","uint32_t ordinalBase = *(uint32_t *)(exportDir + 0x10);");
    number_field(export_address,offsetof(IMAGE_EXPORT_DIRECTORY,NumberOfFunctions),"NumberOfFunctions",exp.NumberOfFunctions,
        "Element count of the DWORD Export Address Table.","uint32_t functionCount = *(uint32_t *)(exportDir + 0x14);");
    number_field(export_address,offsetof(IMAGE_EXPORT_DIRECTORY,NumberOfNames),"NumberOfNames",exp.NumberOfNames,
        "Element count of both the name-pointer table and ordinal table.","uint32_t nameCount = *(uint32_t *)(exportDir + 0x18);");
    hex_number_field(export_address,offsetof(IMAGE_EXPORT_DIRECTORY,AddressOfFunctions),"AddressOfFunctions (RVA)",exp.AddressOfFunctions,
        "Stored RVA of the Export Address Table.","uint32_t functionsRva = *(uint32_t *)(exportDir + 0x1C);");
    pointer_field(export_address,offsetof(IMAGE_EXPORT_DIRECTORY,AddressOfFunctions),"AddressOfFunctions -> VA",base+exp.AddressOfFunctions,
        "RVA of DWORD function RVAs (Export Address Table).","uint32_t *functions = (uint32_t *)(base + *(uint32_t *)(exportDir + 0x1C));");
    hex_number_field(export_address,offsetof(IMAGE_EXPORT_DIRECTORY,AddressOfNames),"AddressOfNames (RVA)",exp.AddressOfNames,
        "Stored RVA of the export name-pointer table.","uint32_t namesRva = *(uint32_t *)(exportDir + 0x20);");
    pointer_field(export_address,offsetof(IMAGE_EXPORT_DIRECTORY,AddressOfNames),"AddressOfNames -> VA",base+exp.AddressOfNames,
        "RVA of DWORD RVAs that point to ASCII export names.","uint32_t *names = (uint32_t *)(base + *(uint32_t *)(exportDir + 0x20));");
    hex_number_field(export_address,offsetof(IMAGE_EXPORT_DIRECTORY,AddressOfNameOrdinals),"NameOrdinals (RVA)",exp.AddressOfNameOrdinals,
        "Stored RVA of the WORD ordinal-index table.","uint32_t ordinalsRva = *(uint32_t *)(exportDir + 0x24);");
    pointer_field(export_address,offsetof(IMAGE_EXPORT_DIRECTORY,AddressOfNameOrdinals),"AddressOfNameOrdinals -> VA",base+exp.AddressOfNameOrdinals,
        "RVA of WORD indexes into AddressOfFunctions; these are indexes, not biased public ordinals.","uint16_t *ordinals = (uint16_t *)(base + *(uint32_t *)(exportDir + 0x24));");
    char exported_dll_name[1024];
    if (read_image_string(base,exp.Name,image_size,exported_dll_name,sizeof exported_dll_name))
        printf("           |      DLL  -> %s\n",exported_dll_name);
    print_full_code(FULL_EXPORT_DIR,module_name,NULL);

    if (!exp.NumberOfNames || exp.NumberOfNames>MAX_EXPORTS ||
        !exp.NumberOfFunctions || exp.NumberOfFunctions>MAX_EXPORTS ||
        !image_range(exp.AddressOfNames,(size_t)exp.NumberOfNames*sizeof(DWORD),image_size) ||
        !image_range(exp.AddressOfNameOrdinals,(size_t)exp.NumberOfNames*sizeof(WORD),image_size) ||
        !image_range(exp.AddressOfFunctions,(size_t)exp.NumberOfFunctions*sizeof(DWORD),image_size)) {
        puts("[!] Invalid or unreasonably large export arrays."); return 0;
    }

    for (DWORD i=0;i<exp.NumberOfNames;i++) {
        DWORD name_rva=0, function_rva=0;
        WORD ordinal_index=0;
        uintptr_t name_slot=base+exp.AddressOfNames+(uintptr_t)i*sizeof(DWORD);
        uintptr_t ordinal_slot=base+exp.AddressOfNameOrdinals+(uintptr_t)i*sizeof(WORD);
        if (read_at(name_slot,&name_rva,sizeof name_rva)!=sizeof name_rva ||
            !image_range(name_rva,1,image_size)) continue;
        char name[1024];
        if (!read_image_string(base,name_rva,image_size,name,sizeof name) || strcmp(name,function_name)) continue;
        if (read_at(ordinal_slot,&ordinal_index,sizeof ordinal_index)!=sizeof ordinal_index ||
            ordinal_index>=exp.NumberOfFunctions) {
            puts("[!] Matching name has an invalid function-table index."); return 0;
        }
        uintptr_t function_slot=base+exp.AddressOfFunctions+(uintptr_t)ordinal_index*sizeof(DWORD);
        if (read_at(function_slot,&function_rva,sizeof function_rva)!=sizeof function_rva ||
            !image_range(function_rva,1,image_size)) {
            puts("[!] Matching export has an invalid function RVA."); return 0;
        }

        header("EXPORT LOOKUP (MATCHED ARRAY ELEMENTS)",name_slot);
        hex_number_field(name_slot,0,"AddressOfNames[i] (RVA)",name_rva,
            "Raw DWORD RVA stored in the matched name-pointer-table element.","uint32_t nameRva = *(uint32_t *)((uintptr_t)names + i * 4);");
        pointer_field(name_slot,0,"AddressOfNames[i] -> name",base+name_rva,
            "The matched DWORD is a name RVA. The search compares its ASCII string exactly.","char *name = (char *)(base + *(uint32_t *)((uintptr_t)names + i * 4));");
        number_field(ordinal_slot,0,"AddressOfNameOrdinals[i]",ordinal_index,
            "Zero-based index selecting the corresponding DWORD in AddressOfFunctions.","uint16_t ordinalIndex = *(uint16_t *)((uintptr_t)ordinals + i * 2);");
        number_field(function_slot,0,"Public ordinal",exp.Base+ordinal_index,
            "Externally visible ordinal: export Base plus the function-table index.","uint32_t ordinal = *(uint32_t *)(exportDir + 0x10) + ordinalIndex;");
        hex_number_field(function_slot,0,"AddressOfFunctions[index] (RVA)",function_rva,
            "Raw DWORD RVA stored in the selected Export Address Table element.","uint32_t functionRva = *(uint32_t *)((uintptr_t)functions + ordinalIndex * 4);");
        pointer_field(function_slot,0,"AddressOfFunctions[index] -> VA",base+function_rva,
            "Function RVA converted to VA. If it falls inside the export directory, it names a forwarder instead of code.","uintptr_t address = base + *(uint32_t *)((uintptr_t)functions + ordinalIndex * 4);");
        print_full_code(FULL_EXPORT_LOOKUP,module_name,function_name);

        uint64_t export_end=(uint64_t)data.VirtualAddress+data.Size;
        if (function_rva>=data.VirtualAddress && (uint64_t)function_rva<export_end) {
            char forwarder[1024];
            if (read_image_string(base,function_rva,image_size,forwarder,sizeof forwarder))
                printf("\n[+] FORWARDED EXPORT: %s -> %s\n",function_name,forwarder);
            else puts("\n[+] FORWARDED EXPORT: target string is unreadable");
            puts("    The reported VA points to a forwarder string, not callable code.");
        } else {
            printf("\n[+] FUNCTION FOUND: %s = ",function_name);
            yellow(); printf("0x%016" PRIXPTR "\n",base+function_rva); normal();
        }
        return base+function_rva;
    }
    printf("[!] Export '%s' was not found by name.\n",function_name);
    return 0;
}

int main(int argc, char **argv) {
    con=GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO info;
    if (con != INVALID_HANDLE_VALUE && GetConsoleScreenBufferInfo(con,&info)) normal_attr=info.wAttributes;
    const char *func_spec=NULL;
    for (int i=1;i<argc;i++) {
        if (!strcmp(argv[i],"--hex")) opt_hex=1;
        else if (!strcmp(argv[i],"--text")) opt_text=1;
        else if (!strcmp(argv[i],"--asm")) opt_asm=1;
        else if (!strcmp(argv[i],"--desc")) opt_desc=1;
        else if (!strcmp(argv[i],"--code")) opt_code=1;
        else if (!strcmp(argv[i],"--code-full")) opt_code_full=1;
        else if (!strcmp(argv[i],"--func")) {
            if (++i>=argc) { fputs("--func requires DLL:Function\n",stderr); return 2; }
            func_spec=argv[i];
        }
        else if (!strcmp(argv[i],"--help") || !strcmp(argv[i],"-h")) { usage(argv[0]); return 0; }
        else { fprintf(stderr,"Unknown option: %s\n",argv[i]); usage(argv[0]); return 2; }
    }
    if (opt_code && opt_code_full) {
        fputs("--code and --code-full are mutually exclusive.\n",stderr);
        return 2;
    }
    char module_name[MAX_PATH]="kernel32.dll";
    char function_name[1024]="";
    if (func_spec) {
        const char *colon=strrchr(func_spec,':');
        size_t module_len=colon ? (size_t)(colon-func_spec) : 0;
        if (!colon || !module_len || !colon[1] || module_len>=sizeof module_name ||
            strlen(colon+1)>=sizeof function_name) {
            fputs("Invalid --func value; expected DLL:Function (for example KERNEL32.dll:LoadLibraryA).\n",stderr);
            return 2;
        }
        memcpy(module_name,func_spec,module_len); module_name[module_len]=0;
        strcpy(function_name,colon+1);
    }
    printf("Windows x64 memory inspector | HEX=%s TEXT=%s ASM=%s DESC=%s CODE=%s CODE_FULL=%s\n",
           opt_hex?"ON":"OFF",opt_text?"ON":"OFF",opt_asm?"ON":"OFF",opt_desc?"ON":"OFF",
           opt_code?"ON":"OFF",opt_code_full?"ON":"OFF");
    uintptr_t module=resolver(module_name);
    uintptr_t found=func_spec && module ? explain_export(module,module_name,function_name) : module;
    if (opt_asm) {
        puts("\nASM sample: bytes at resolver() (executable code, independent of loader pointers)");
        dump_asm((uintptr_t)(void *)&resolver);
    }
    normal();
    return found ? 0 : 1;
}
