#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define ELF_MAGIC "\x7f""ELF"
#define EI_CLASS 4
#define ELFCLASS64 2

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} Elf64_Phdr;

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: arbextract <xbl_config.img>\n");
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    /* Read ELF header */
    unsigned char ehdr[64];
    if (fread(ehdr, 1, sizeof(ehdr), f) != sizeof(ehdr)) {
        fprintf(stderr, "Failed to read ELF header\n");
        return 1;
    }

    if (memcmp(ehdr, ELF_MAGIC, 4) != 0 || ehdr[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "Not a valid ELF64 file\n");
        return 1;
    }

    uint64_t e_phoff   = *(uint64_t *)(ehdr + 0x20);
    uint16_t e_phentsz = *(uint16_t *)(ehdr + 0x36);
    uint16_t e_phnum   = *(uint16_t *)(ehdr + 0x38);

    /* Locate candidate HASH segment (last non-empty PT_NULL) */
    uint64_t hash_off = 0, hash_size = 0;

    for (int i = e_phnum - 1; i >= 0; i--) {
        Elf64_Phdr ph;

        fseek(f, e_phoff + (uint64_t)i * e_phentsz, SEEK_SET);
        fread(&ph, 1, sizeof(ph), f);

        if (ph.p_type == 0 && ph.p_filesz > 0) {
            hash_off  = ph.p_offset;
            hash_size = ph.p_filesz;
            break;
        }
    }

    if (!hash_size) {
        fprintf(stderr, "HASH segment not found\n");
        return 1;
    }

    /* Read HASH segment */
    uint8_t *seg = malloc(hash_size);
    fseek(f, hash_off, SEEK_SET);
    fread(seg, 1, hash_size, f);
    fclose(f);

    /* Scan for Hash Table Segment Header */
    uint32_t version, common_sz, qti_sz, oem_sz, hash_tbl_sz;

    size_t header_off = 0;
    int found = 0;

    for (size_t off = 0; off + 36 <= hash_size && off < 0x1000; off += 4) {
        memcpy(&version,       seg + off + 0,  4);
        memcpy(&common_sz,     seg + off + 4,  4);
        memcpy(&qti_sz,        seg + off + 8,  4);
        memcpy(&oem_sz,        seg + off + 12, 4);
        memcpy(&hash_tbl_sz,   seg + off + 16, 4);

        if (version < 1 || version > 10)
            continue;
        if (common_sz > 0x1000 || oem_sz > 0x4000 || hash_tbl_sz > 0x4000)
            continue;
        if (off + 36 + common_sz + qti_sz + oem_sz > hash_size)
            continue;

        header_off = off;
        found = 1;
        break;
    }

    if (!found) {
        fprintf(stderr, "Hash table header not found\n");
        free(seg);
        return 1;
    }

    /* Locate OEM Metadata */
    uint64_t oem_md_off = header_off + 36 + common_sz + qti_sz;
    uint32_t major, minor, arb;

    memcpy(&major, seg + oem_md_off + 0, 4);
    memcpy(&minor, seg + oem_md_off + 4, 4);
    memcpy(&arb,   seg + oem_md_off + 8, 4);

    printf("OEM Metadata Major Version : %u\n", major);
    printf("OEM Metadata Minor Version : %u\n", minor);
    printf("ARB (Anti-Rollback)       : %u\n", arb);

    free(seg);
    return 0;
}

