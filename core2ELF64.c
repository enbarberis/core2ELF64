/* For original work visit 
 * https://bitbucket.org/renorobert/core2elf.git
 *
 * Credits to Reno Robert and Silvio Cesare
 *
 * Barberis Enrico - 2018
 * */

#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <elf.h>

/* Section strings */
const char shstr[] =
"\0"
".shstrtab\0"
".interp\0"
".symtab\0"
".strtab\0"
".hash\0"
".dynsym\0"
".dynstr\0"
".rel.got\0"
".rel.bss\0"
".rel.plt\0"
".rela.plt\0"
".init\0"
".plt\0"
".text\0"
".fini\0"
".rodata\0"
".data\0"
".ctors\0"
".dtors\0"
".got\0"
".dynamic\0"
".bss\0"
".comment\0"
".note\0"
".eh_frame_hdr\0"
".eh_frame\0"
".init_array\0"
".fini_array\0"
".got.plt\0"
".rel.dyn\0"
".rela.dyn\0"
".gnu.version\0"
".gnu.version_r\0"
".gnu.hash\0"
".tbss\0"
".jcr\0";


/* Print error message and quit */
void die(const char *fmt, ...);

/* Read file at desired offset and store the content in a malloc'd buffer */
char* xget(int fd, int off, size_t sz);

/* Convert segment type to the corresponding string */
char* seg_type_to_str(Elf64_Word type);

/* Get index of a desired section name */
int sec_index(char *sec_name);

int main(int argc, char **argv)
{
    int i, j; //Iteration variable
    int in; //Core Dump file descriptor
    char core_e_ident[EI_NIDENT];
    Elf64_Ehdr *core_ehdr;
    Elf64_Phdr *core_phdr;

    /* Checks on input file */    
    if ( argc != 3 ) 
        die("Usage: %s <core dump> <output file>", argv[0]);

    in =  open(argv[1], O_RDONLY);
    if (in < 0) die("Coudln't open file: %s", argv[1]);

    if (read(in, core_e_ident, sizeof(core_e_ident)) != sizeof(core_e_ident)) 
        die("Read error");

    if(strncmp(core_e_ident, ELFMAG, SELFMAG))
        die("%s is not an ELF file!\n", argv[1]);

    if(core_e_ident[EI_CLASS] != ELFCLASS64)
        die("This version supports only 64 bit core dumps!");

    if(core_e_ident[EI_DATA] != ELFDATA2LSB)
        die("This version supports only Little Endian!\n");

    /* Read ELF header */
    if (lseek(in, 0, SEEK_SET) < 0) die("Seek error");
    core_ehdr = (Elf64_Ehdr *) malloc(sizeof(Elf64_Ehdr));
    if (core_ehdr == NULL) die("malloc error");
    if (read(in, core_ehdr, sizeof(Elf64_Ehdr)) != sizeof(Elf64_Ehdr)) 
        die("Read error");

    /* Additional checks on the ELF files */
    if (core_ehdr->e_type != ET_CORE) die("%s is not a core dump!", argv[1]);
    if (core_ehdr->e_machine != EM_X86_64)
        die("This version supports only 64 bit core dumps!");

    /* Input file is OK, now read program/segment header */
    unsigned int core_phdr_size = core_ehdr->e_phentsize*core_ehdr->e_phnum;
    if (lseek(in, core_ehdr->e_phoff, SEEK_SET) < 0) die("Seek error");
    core_phdr = (Elf64_Phdr *) malloc(core_phdr_size);
    if (core_phdr == NULL) die("malloc error");
    if (read(in, core_phdr, core_phdr_size) < core_phdr_size) die("Read error");

    /* Print all core dump segments */
    printf("\n[*] Core dump contains the following segments:\n\n");
    printf("Index  %16s   Virt. addr. start    Virt. addr. end      Flags\n", "Type");
    for(i=0; i<core_ehdr->e_phnum; i++)
    {
        printf("[%4d] %16s   0x%016lx - 0x%016lx   %c %c %c\n", 
                i,
                seg_type_to_str(core_phdr[i].p_type),
                core_phdr[i].p_vaddr, 
                core_phdr[i].p_vaddr+core_phdr[i].p_memsz,
                core_phdr[i].p_flags & PF_R ? 'R' : ' ',
                core_phdr[i].p_flags & PF_W ? 'W' : ' ',
                core_phdr[i].p_flags & PF_X ? 'X' : ' ');
    }

    /* Search for text segments! */
    int core_text_seg_index = -1;

    printf("\n[*] Valid text segments: ");
    for(i=0; i<core_ehdr->e_phnum; i++)
    {
        /* Read first 4 bytes of the segment to see if it is ELF */
        char *seg_data = xget(in, core_phdr[i].p_offset, SELFMAG);
        if( core_phdr[i].p_type == PT_LOAD &&
                core_phdr[i].p_flags == (PF_R | PF_X) &&
                strncmp(seg_data, ELFMAG, SELFMAG) == 0 )
        {
            printf("%d ", i);
            if ( (core_phdr[i].p_vaddr & (~0xfffff)) == 0x400000 )
                core_text_seg_index = i;
        } 
        if(seg_data != NULL) free(seg_data);
    }
    printf("\n");
    if(core_text_seg_index == -1)
    {
        printf("Unable to find a text segment near virtual address 0x400000, " 
                "please specify a text segment index (usually 1): ");
        scanf("%d", &core_text_seg_index);
    }  
    printf("[*] Text segment index = %d\n", core_text_seg_index);

    /* Retrive text segment data */
    char *text_seg_data = xget(in, core_phdr[core_text_seg_index].p_offset, 
            core_phdr[core_text_seg_index].p_filesz);
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    ehdr = (Elf64_Ehdr *) text_seg_data;
    phdr = (Elf64_Phdr *) &text_seg_data[ehdr->e_phoff];
    
    /* Print reconstructed segment/program header */ 
    printf("[*] Reconstructed Program Header:\n\n");
    printf("Index  %16s   Virt. addr. start    Virt. addr. end      Flags\n", "Type");
    for(i=0; i<ehdr->e_phnum; i++)
    {
        printf("[%4d] %16s   0x%016lx - 0x%016lx   %c %c %c\n", 
                i,
                seg_type_to_str(phdr[i].p_type),
                phdr[i].p_vaddr, 
                phdr[i].p_vaddr+phdr[i].p_memsz,
                phdr[i].p_flags & PF_R ? 'R' : ' ',
                phdr[i].p_flags & PF_W ? 'W' : ' ',
                phdr[i].p_flags & PF_X ? 'X' : ' ');
    }

    /* Find text segment, data segment and dynamic segment */
    int text_seg_index=-1, data_seg_index=-1, dyn_seg_index=-1;

    for(i=0; i<ehdr->e_phnum; i++)
    {
        if( phdr[i].p_type == PT_LOAD && phdr[i].p_flags == (PF_R | PF_X) &&
                phdr[i].p_vaddr < ehdr->e_entry &&
                phdr[i].p_vaddr + phdr[i].p_memsz > ehdr->e_entry)
        {
            text_seg_index = i;
        }

        if( phdr[i].p_type == PT_LOAD && (phdr[i].p_flags & PF_W) )
        {
            data_seg_index = i;
        }

        if( phdr[i].p_type == PT_DYNAMIC )
        {
            dyn_seg_index = i;
        }
    }

    /* Print found segments */
    if(text_seg_index == -1)
        die("Unable to find text segment");
    else
        printf("\n[*] Text segment:    0x%lx - 0x%lx\n", 
                phdr[text_seg_index].p_vaddr,
                phdr[text_seg_index].p_vaddr + phdr[text_seg_index].p_memsz);

    if(data_seg_index == -1)
        printf("[*] Unable to find data segment\n");
    else
        printf("[*] Data segment:    0x%lx - 0x%lx\n", 
                phdr[data_seg_index].p_vaddr,
                phdr[data_seg_index].p_vaddr + phdr[data_seg_index].p_memsz);

    if(dyn_seg_index == -1)
        printf("[*] Unable to find dynamic segment\n");
    else
        printf("[*] Dynamic segment: 0x%lx - 0x%lx\n", 
                phdr[dyn_seg_index].p_vaddr,
                phdr[dyn_seg_index].p_vaddr + phdr[dyn_seg_index].p_memsz);


    /* Recover the content of found segments */
    char **seg_data = malloc(sizeof(char *)*ehdr->e_phnum);
    if(seg_data == NULL) die("Malloc error");

    for(i=0; i<ehdr->e_phnum; i++)
    {
        for (j=0; j<core_ehdr->e_phnum; j++)   
        {
            /* If executable is PIE */
            if(ehdr->e_type == ET_DYN)
            {
                if(  phdr[i].p_vaddr >= 
                     core_phdr[j].p_vaddr - core_phdr[core_text_seg_index].p_vaddr &&
                      phdr[i].p_vaddr < core_phdr[j].p_vaddr + core_phdr[j].p_filesz - core_phdr[core_text_seg_index].p_vaddr)
                {
                    //printf("%d recover with %d\n",i,j);
                    seg_data[i] = xget( in,
                            core_phdr[j].p_offset + phdr[i].p_vaddr - (core_phdr[j].p_vaddr - core_phdr[core_text_seg_index].p_vaddr),
                            phdr[i].p_filesz );
                    break;
                }
            }
            else
            {
                if(  phdr[i].p_vaddr >= core_phdr[j].p_vaddr &&
                     phdr[i].p_vaddr < core_phdr[j].p_vaddr + core_phdr[j].p_filesz  )
                {
                    //printf("%d recover with %d\n",i,j);
                    seg_data[i] = xget( in,
                            core_phdr[j].p_offset + phdr[i].p_vaddr - core_phdr[j].p_vaddr,
                            phdr[i].p_filesz );
                    break;
                }
            }
        }
    }

    /* Write recovered segments to output file */
    int eof = 0;    //File offset to end of file (where section strings will be written)
    int out = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IXUSR);
    if (out < 0) die("Failed to create output file %s", argv[2]);

    for (i=0; i<ehdr->e_phnum; i++)
    {
        if (lseek(out, phdr[i].p_offset, SEEK_SET) < 0)
            die("Error seek");

        if (write(out, seg_data[i], phdr[i].p_filesz) != phdr[i].p_filesz)
            die("Write error");

        if (phdr[i].p_offset + phdr[i].p_filesz > eof)
            eof = phdr[i].p_offset + phdr[i].p_filesz;
    }
    
    /* Write section strings */
    if (lseek(out, eof, SEEK_SET) < 0)
        die("Error Seek");
    if (write(out, shstr, sizeof(shstr)) != sizeof(shstr))
        die("Error writing shstr");
    
    /* Reset section header offset and number */
    ehdr->e_shoff = eof + sizeof(shstr);
    ehdr->e_shnum = 0;
    ehdr->e_shstrndx = 1;

    /*********************************/
    /* Section header reconstruction */
    /*********************************/
    Elf64_Shdr shdr;
    Elf64_Word interp_index = 0; //Store interp section index needed below

    /* Recover simple sections (1:1 matching with segments) */
    printf("\n[*] Recovered sections:\n");
    
    /* NULL section */
    memset(&shdr, 0, sizeof(shdr));
    if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) die("Write Error");
    ehdr->e_shnum++;

    /* .shstrtab */
    shdr.sh_name = sec_index(".shstrtab");
    shdr.sh_type = SHT_STRTAB;
    shdr.sh_addr = 0;
    shdr.sh_offset = ehdr->e_shoff - sizeof(shstr);
    shdr.sh_size = sizeof(shstr);
    shdr.sh_flags = 0;
    shdr.sh_link = 0;
    shdr.sh_info = 0;
    shdr.sh_addralign = 1;
    shdr.sh_entsize = 0;

    if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) die("Error .shstrtab");
    ehdr->e_shnum++;

    for (i=0; i<ehdr->e_phnum; i++)
    {
        switch(phdr[i].p_type)
        {
            /* .interp */
            case PT_INTERP:
                shdr.sh_name = sec_index(".interp");
                shdr.sh_type = SHT_PROGBITS;
                shdr.sh_addr = phdr[i].p_vaddr;
                shdr.sh_offset = phdr[i].p_offset;
                shdr.sh_size = phdr[i].p_filesz;
                shdr.sh_flags = SHF_ALLOC;
                shdr.sh_link = 0;
                shdr.sh_info = 0;
                shdr.sh_addralign = 1;
                shdr.sh_entsize = 0;
                interp_index = ehdr->e_shnum;
                
                if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) die("Error .interp");
                ehdr->e_shnum++;
                printf("\t.interp\n");
                break;

            /* .dynamic */
            case PT_DYNAMIC:
                shdr.sh_name = sec_index(".dynamic");
                shdr.sh_type = SHT_DYNAMIC;
                shdr.sh_addr = phdr[i].p_vaddr;
                shdr.sh_offset = phdr[i].p_offset;
                shdr.sh_size = phdr[i].p_filesz;
                shdr.sh_flags = SHF_ALLOC;
                shdr.sh_link = 0;
                shdr.sh_info = 0;
                shdr.sh_addralign = 8;
                shdr.sh_entsize = 16; 
                
                if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) die("Error .dynamic");
                ehdr->e_shnum++;
                printf("\t.dynamic\n");
                break;

            /* .note */
            case PT_NOTE:
                shdr.sh_name = sec_index(".note");
                shdr.sh_type = SHT_NOTE;
                shdr.sh_addr = phdr[i].p_vaddr;
                shdr.sh_offset = phdr[i].p_offset;
                shdr.sh_size = phdr[i].p_filesz;
                shdr.sh_flags = SHF_ALLOC;
                shdr.sh_link = 0;
                shdr.sh_info = 0;
                shdr.sh_addralign = 4;
                shdr.sh_entsize = 0;

                if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) die("Error .note");
                ehdr->e_shnum++;
                printf("\t.note\n");
                break;

            /* .tbss */
            case PT_TLS:
                shdr.sh_name = sec_index(".tbss");
                shdr.sh_type = SHT_NOBITS;
                shdr.sh_addr = phdr[i].p_vaddr;
                shdr.sh_offset = phdr[i].p_offset;
                shdr.sh_size = phdr[i].p_memsz;
                shdr.sh_flags = SHF_ALLOC | SHF_WRITE | SHF_TLS;
                shdr.sh_link = 0;
                shdr.sh_info = 0;
                shdr.sh_addralign = 8;
                shdr.sh_entsize = 0;

                if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) die("Error .tbss");
                ehdr->e_shnum++;
                printf("\t.tbss\n");
                break;

            /* .eh_frame_hdr and .eh_frame */
            case PT_GNU_EH_FRAME:
                shdr.sh_name = sec_index(".eh_frame_hdr");
                shdr.sh_type = SHT_PROGBITS;
                shdr.sh_addr = phdr[i].p_vaddr;
                shdr.sh_offset = phdr[i].p_offset;
                shdr.sh_size = phdr[i].p_filesz;
                shdr.sh_flags = SHF_ALLOC;
                shdr.sh_link = 0;
                shdr.sh_info = 0;
                shdr.sh_addralign = 4;
                shdr.sh_entsize = 0;

                if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) die("Error .eh_frame_hdr");
                ehdr->e_shnum++;
                printf("\t.eh_frame\n");

                /* .eh_frame_hdr is always followed by .eh_frame that is last section in text seg */
                shdr.sh_name = sec_index(".eh_frame");
                shdr.sh_type = SHT_PROGBITS;
                shdr.sh_addr = phdr[i].p_vaddr + phdr[i].p_filesz;
                shdr.sh_offset = phdr[i].p_offset + phdr[i].p_filesz;
                shdr.sh_size =  (phdr[text_seg_index].p_vaddr + phdr[text_seg_index].p_filesz) -
                                (phdr[i].p_vaddr + phdr[i].p_filesz);
                shdr.sh_flags = SHF_ALLOC;
                shdr.sh_link = 0;
                shdr.sh_info = 0;
                shdr.sh_addralign = 8;
                shdr.sh_entsize = 0;    

                if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) die("Error .eh_frame");
                ehdr->e_shnum++;
                printf("\t.eh_frame_hdr\n");
                break;
        }
    }  

    /* .bss (it is always at the end of the data segment) */
    if(data_seg_index != -1)
    {
        shdr.sh_name = sec_index(".bss");
        shdr.sh_type = SHT_NOBITS;
        shdr.sh_addr = phdr[data_seg_index].p_vaddr + phdr[data_seg_index].p_filesz;
        shdr.sh_offset = phdr[data_seg_index].p_offset + phdr[data_seg_index].p_filesz;
        shdr.sh_size = phdr[data_seg_index].p_memsz - phdr[data_seg_index].p_filesz;
        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 16;
        shdr.sh_entsize = 0;
    
        if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) die("Error .bss");
        ehdr->e_shnum++;
        printf("\t.bss\n");
    }
    
    /* Avoid to check .dynamic segment for static binaries */
    if(dyn_seg_index == -1)
        goto section_rebuild_end;

    /* Ok easy mappings done, Now use .dynamic section to recover other info */
    Elf64_Dyn *dyn = (Elf64_Dyn *) seg_data[dyn_seg_index];

    /* Recover values from .dynamic */
    Elf64_Addr init=0, fini=0, init_array=0, fini_array=0, gnu_hash=0, strtab=0,
               symtab=0, pltgot=0, jmprel=0, rel=0, rela=0, verneed=0, versym=0;   
    Elf64_Xword init_arraysz=0, fini_arraysz=0, strsz=0, syment=0, pltrelsz=0, 
                pltrel=0, relsz=0, relasz=0, relent=0, relaent=0, verneednum=0,
                bindnow=0;
    /* Bool var to tell if binary is PIE or not. If PIE some symbols need
     * to be changed by an offset */ 
    uint8_t pie = ehdr->e_type == ET_DYN;

    for(; dyn->d_tag != DT_NULL; ++dyn)
    {
        switch(dyn->d_tag)
        { 
            case DT_BIND_NOW: //Full relro
                bindnow = 1;
            break;

            case DT_INIT:
                init = dyn->d_un.d_ptr;
                break;

            case DT_FINI:
                fini = dyn->d_un.d_ptr;
                break;

            case DT_INIT_ARRAY:
                init_array = dyn->d_un.d_ptr;
                break;

            case DT_INIT_ARRAYSZ:
                init_arraysz = dyn->d_un.d_val;
                break;

            case DT_FINI_ARRAY:
                fini_array = dyn->d_un.d_ptr;
                break;

            case DT_FINI_ARRAYSZ:
                fini_arraysz = dyn->d_un.d_val;
                break;

            case DT_GNU_HASH:
                if(pie) dyn->d_un.d_ptr -= core_phdr[core_text_seg_index].p_vaddr;
                gnu_hash = dyn->d_un.d_ptr;
                break;

            case DT_STRTAB:
                if(pie) dyn->d_un.d_ptr -= core_phdr[core_text_seg_index].p_vaddr;
                strtab = dyn->d_un.d_ptr;
                break;
            
            case DT_SYMTAB:
                if(pie) dyn->d_un.d_ptr -= core_phdr[core_text_seg_index].p_vaddr;
                symtab = dyn->d_un.d_ptr;
                break;

            case DT_STRSZ:
                strsz = dyn->d_un.d_val;
                break;

            case DT_SYMENT:
                syment = dyn->d_un.d_val;
                break;

            case DT_PLTGOT:
                if(pie) dyn->d_un.d_ptr -= core_phdr[core_text_seg_index].p_vaddr;
                pltgot = dyn->d_un.d_ptr;
                break;

            case DT_PLTRELSZ:
                pltrelsz = dyn->d_un.d_val;
                break;
            
            case DT_PLTREL:
                pltrel = dyn->d_un.d_val;
                break;

            case DT_JMPREL:
                if(pie) dyn->d_un.d_ptr -= core_phdr[core_text_seg_index].p_vaddr;
                jmprel = dyn->d_un.d_ptr;
                break;

            case DT_RELA:
                if(pie) dyn->d_un.d_ptr -= core_phdr[core_text_seg_index].p_vaddr;
                rela = dyn->d_un.d_ptr;
                break;
            
            case DT_RELASZ:
                relasz = dyn->d_un.d_val;
                break;

            case DT_RELAENT:
                relaent = dyn->d_un.d_val;
                break;
            
            case DT_REL:
                rel = dyn->d_un.d_ptr;
                break;
            
            case DT_RELSZ:
                relsz = dyn->d_un.d_val;
                break;

            case DT_RELENT:
                relent = dyn->d_un.d_val;
                break;

            case DT_VERNEED:
                verneed = dyn->d_un.d_ptr;
                break;

            case DT_VERNEEDNUM:
                verneednum = dyn->d_un.d_val;
                break;

            case DT_VERSYM:
                if(pie) dyn->d_un.d_ptr -= core_phdr[core_text_seg_index].p_vaddr;
                versym = dyn->d_un.d_ptr;
                break;

            default:
                //printf("%ld\n", dyn->d_tag);
                break;
        }
    }
    
    /* If PIE rewrite correct value to .dynamic section */
    if(pie)
    {
        uint64_t fd_pos;

        if ((fd_pos = lseek(out, 0, SEEK_CUR)) < 0) die("Error seek");

        if (lseek(out, phdr[dyn_seg_index].p_offset, SEEK_SET) < 0)
            die("Error seek");

        if (write(out, seg_data[dyn_seg_index], phdr[dyn_seg_index].p_filesz) != 
                phdr[dyn_seg_index].p_filesz)
            die("Write error");
        
        if (lseek(out, fd_pos, SEEK_SET) < 0)
            die("Error seek");
    }    


    /* .init_array - In data segment, contains pointer to code to be
     * execute at the beginning */
    if(init_array != 0 && init_arraysz != 0)
    {
        shdr.sh_name = sec_index(".init_array");
        shdr.sh_type = SHT_INIT_ARRAY;
        shdr.sh_addr = init_array;
        shdr.sh_offset = init_array - (phdr[data_seg_index].p_vaddr - 
                phdr[data_seg_index].p_offset);
        shdr.sh_size = init_arraysz;
        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 8;
        shdr.sh_entsize = 0;

        if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) die("Error .init_array");
        ehdr->e_shnum++;
        printf("\t.init_array\n");
    }

    /* .fini_array - In data segment, contains pointer to code to be
     * execute at the end */
    if(fini_array != 0 && fini_arraysz != 0)
    {
        shdr.sh_name = sec_index(".fini_array");
        shdr.sh_type = SHT_FINI_ARRAY;
        shdr.sh_addr = fini_array;
        shdr.sh_offset = fini_array - (phdr[data_seg_index].p_vaddr -
                phdr[data_seg_index].p_offset);
        shdr.sh_size = fini_arraysz;
        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 8;
        shdr.sh_entsize = 0;

        if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) die("Error .fini_array");
        ehdr->e_shnum++;
        printf("\t.fini_array\n");
    }

    /* .dynstr, usually followed by versym */
    Elf64_Word dynstr_index = 0;
    if(strtab != 0 && versym != 0)
    {
        shdr.sh_name = sec_index(".dynstr");
        shdr.sh_type = SHT_STRTAB;
        shdr.sh_addr = strtab;
        shdr.sh_offset = shdr.sh_addr - phdr[text_seg_index].p_vaddr;
        shdr.sh_size = versym - shdr.sh_addr;
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 1;
        shdr.sh_entsize = 0;

        dynstr_index = ehdr->e_shnum;
        if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) die("Error .dynstr");
        ehdr->e_shnum++;
        printf("\t.dynstr\n");
    }

    /* .dynsym - Structure containing information needed to locate and relocate a 
     * program's symbolic definitions and references. */
    Elf64_Word dynsym_index = 0; 
    if(symtab !=0 && strtab !=0)
    {
        shdr.sh_name = sec_index(".dynsym");
        shdr.sh_type = SHT_DYNSYM;
        shdr.sh_addr = symtab;
        shdr.sh_offset = shdr.sh_addr - phdr[text_seg_index].p_vaddr;
        shdr.sh_size = strtab - symtab;
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_link = dynstr_index;
        shdr.sh_info = interp_index;
        shdr.sh_addralign = 8;
        shdr.sh_entsize = sizeof(Elf64_Sym);

        dynsym_index = ehdr->e_shnum;
        if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) die("Error .dynsym");
        ehdr->e_shnum++;
        printf("\t.dynsym\n");
    }

    /* .got.plt - Global Offst Table for Procedure Linkage Table
     * pltrelsz = total size in bytes of the relocation entries associated with the plt
     * relaent/relent = size of a relocation entry */
    uint64_t got_entries = 0;
    if(pltrel != 0 && pltrelsz !=0 && (relent != 0 || relaent != 0) && pltgot != 0)
    {
        if(pltrel == DT_RELA)
            got_entries = ((pltrelsz/relaent) + 3);
        else 
            got_entries = ((pltrelsz/relent) + 3);

        shdr.sh_size = got_entries * sizeof(Elf64_Addr);
        shdr.sh_name = sec_index(".got.plt");
        shdr.sh_type = SHT_PROGBITS;
        shdr.sh_addr = pltgot;
        shdr.sh_offset = pltgot - (phdr[data_seg_index].p_vaddr -
                phdr[data_seg_index].p_offset);
        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 8;
        shdr.sh_entsize = 0;

        if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) die("Error .got.plt");
        ehdr->e_shnum++;
        printf("\t.got.plt\n");
    }

    /* .data - resides after .got.plt */
    if(pltgot != 0 && got_entries != 0)
    {
        shdr.sh_name = sec_index(".data");
        shdr.sh_type = SHT_PROGBITS;
        shdr.sh_addr = pltgot + got_entries * sizeof(Elf64_Addr);
        shdr.sh_offset = shdr.sh_addr - (phdr[data_seg_index].p_vaddr -
                phdr[data_seg_index].p_offset);
        shdr.sh_size = (phdr[data_seg_index].p_vaddr + phdr[data_seg_index].p_filesz) - 
            (pltgot + (got_entries * sizeof(Elf64_Addr)));
        shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 8;
        shdr.sh_entsize = 0;
        if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) die("Error .data");
        ehdr->e_shnum++;
        printf("\t.data\n");
    }

    
    /*.plt*/
    Elf64_Word plt_addr = 0;
    Elf64_Word plt_index = 0;

    /* Start from init then search for .plt pattern */
    if(init != 0 && pltgot != 0 && got_entries != 0)
    {
        uint64_t off = init, tmp;
        char *ptr = seg_data[text_seg_index] + 
            init - phdr[text_seg_index].p_vaddr; //.init offset
        char *max_ptr = seg_data[text_seg_index] + phdr[text_seg_index].p_filesz - 14;
        char pattern[12] = {0xff, 0x35,                 //push
                            0x00, 0x00, 0x00, 0x00,     //rip+xxxx=GOT+8
                            0xff, 0x25,                 //jmp
                            0x00, 0x00, 0x00, 0x00};    //rip+xxxx=GOT+10
        while(ptr < max_ptr)
        {
            tmp = pltgot + 2 - off;
            memcpy(pattern+2, &tmp, 4);
            tmp = pltgot + 4 - off;
            memcpy(pattern+8, &tmp, 4);
            if( strncmp(ptr, pattern, 14) == 0 )
            {
                plt_addr = off;
                break;
            }

            ptr++;
            off++;
        }
        if(plt_addr == 0)
            goto section_rebuild_end;

        shdr.sh_name = sec_index(".plt");
        shdr.sh_type = SHT_PROGBITS;
        shdr.sh_addr = plt_addr;
        shdr.sh_offset = shdr.sh_addr - phdr[text_seg_index].p_vaddr;
        shdr.sh_size = (got_entries - 2) * 16;
        shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 16;
        shdr.sh_entsize = 16;

        plt_index = ehdr->e_shnum;
        if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) die("Error .got.plt");
        ehdr->e_shnum++;
        printf("\t.plt\n");
    }

    /* .init - is just before .plt */
    if(init != 0 && plt_addr != 0)
    {
        shdr.sh_name = sec_index(".init");
        shdr.sh_type = SHT_PROGBITS;
        shdr.sh_addr = init;
        shdr.sh_offset = init - phdr[text_seg_index].p_vaddr;
        shdr.sh_size = plt_addr - init; //Not 100% correct
        shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 4;
        shdr.sh_entsize = 0;

        if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) die("Error .got.plt");
        ehdr->e_shnum++;
        printf("\t.init\n");
    }

    /* .rel.dyn or .rela.dyn */
    if( (rela != 0 && relaent !=0) || (rel != 0 && relent != 0) )
    {
        if(rela != 0 && relaent != 0)
        {
            shdr.sh_name = sec_index(".rela.dyn");
            shdr.sh_type = SHT_RELA;
            shdr.sh_addr = rela;
            shdr.sh_entsize = relaent; 
            if(jmprel)
                shdr.sh_size = jmprel - shdr.sh_addr;
            else
                shdr.sh_size = relasz;
        }
        else
        {
            shdr.sh_name = sec_index(".rel.dyn");
            shdr.sh_type = SHT_REL;
            shdr.sh_addr = rel;
            shdr.sh_entsize = relent;
            if(jmprel)
                shdr.sh_size = jmprel - shdr.sh_addr;
            else
                shdr.sh_size = relsz;
        }

        shdr.sh_offset = shdr.sh_addr - phdr[text_seg_index].p_vaddr;
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_link = dynsym_index;    
        shdr.sh_info = 0;
        shdr.sh_addralign = 8;

        if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr))
            die("Error .rel.dyn or .rela.dyn");
        ehdr->e_shnum++;
        if(rela != 0)
            printf("\t.rela.dyn\n");
        else
            printf("\t.rel.dyn\n");
            
    }

    /* .rel.plt or .rela.plt */
    if((relent != 0 || relaent != 0) && init != 0 && jmprel != 0)      
    {
        if(pltrel == DT_RELA)
        {
            shdr.sh_name = sec_index(".rela.plt");
            shdr.sh_type = SHT_RELA;
            shdr.sh_entsize = relaent;
        }
        else
        {
            shdr.sh_name = sec_index(".rel.plt");
            shdr.sh_type = SHT_REL;
            shdr.sh_entsize = relent;
        }
        shdr.sh_addr = jmprel;
        shdr.sh_offset = jmprel - phdr[text_seg_index].p_vaddr;
        shdr.sh_size = init - jmprel;
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_link = dynsym_index;            
        shdr.sh_info = plt_index;    
        shdr.sh_addralign = 8;

        if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr))
            die("Error .rel.dyn or .rela.dyn");
        ehdr->e_shnum++;
        if(pltrel == DT_RELA)
            printf("\t.rela.plt\n");
        else
            printf("\t.rel.plt\n");
    }

    /* .text - right after .plt, each plt entry require 16 bytes */
    /* TODO .plt.got is always present ? */
    if(plt_addr != 0 && got_entries != 0 && fini != 0)
    {
        shdr.sh_name = sec_index(".text");
        shdr.sh_type = SHT_PROGBITS;
        shdr.sh_addr = ((plt_addr + (got_entries - 2) * 16) + 8);
        if(shdr.sh_addr & ~0xf)
            shdr.sh_addr = (shdr.sh_addr + 0x10) & ~0xf;
        shdr.sh_offset = shdr.sh_addr - phdr[text_seg_index].p_vaddr;
        shdr.sh_size = fini - ehdr->e_entry;
        shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 16;
        shdr.sh_entsize = 0;

        if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) die("Error .text");
        ehdr->e_shnum++;
        printf("\t.text\n");
    }

    /* .fini */
    /* TODO - find size*/
    if(fini != 0)
    {
        shdr.sh_name = sec_index(".fini");
        shdr.sh_type = SHT_PROGBITS;
        shdr.sh_addr = fini;
        shdr.sh_offset = fini - phdr[text_seg_index].p_vaddr;
        shdr.sh_size = 1;       
        shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
        shdr.sh_link = 0;
        shdr.sh_info = 0;
        shdr.sh_addralign = 4;
        shdr.sh_entsize = 0;

        if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) die("Error .fini");
        ehdr->e_shnum++;
        printf("\t.fini\n");
    }

    /* .gnu.version */
    if(versym != 0 && strtab != 0 && symtab != 0)
    {
        shdr.sh_name = sec_index(".gnu.version");
        shdr.sh_type = SHT_GNU_versym;
        shdr.sh_addr = versym;
        shdr.sh_offset = versym - phdr[text_seg_index].p_vaddr;
        shdr.sh_size = ((strtab - symtab) / sizeof(Elf64_Sym)) * sizeof(Elf64_Half);
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_link = dynsym_index;
        shdr.sh_info = 0;
        shdr.sh_addralign = 2;
        shdr.sh_entsize = 2;

        if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) die("Error .gnu.version");
        ehdr->e_shnum++;
        printf("\t.gnu.version\n");
    }

    /* .gnu_versioni_r - before .rel or .rela */
    if(verneed != 0 && verneednum != 0 && pltrel != 0)
    {
        shdr.sh_name = sec_index(".gnu.version_r");
        shdr.sh_type = SHT_GNU_verneed;
        shdr.sh_addr = verneed;
        shdr.sh_offset = verneed - phdr[text_seg_index].p_vaddr;

        if(pltrel == DT_RELA)
            shdr.sh_size = rela - verneed;
        else
            shdr.sh_size = rel - verneed;

        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_link = dynstr_index;
        shdr.sh_info = verneednum;
        shdr.sh_addralign = 8;
        shdr.sh_entsize = 0;

        if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) die("Error .gnu_version_r");
        ehdr->e_shnum++;
        printf("\t.gnu_version_r\n");
    }

    /* .gnu.hash */
    if(gnu_hash != 0 && symtab != 0)
    {
        shdr.sh_name = sec_index(".gnu.hash");
        shdr.sh_type = SHT_GNU_HASH;
        shdr.sh_addr = gnu_hash;
        shdr.sh_offset = gnu_hash - phdr[text_seg_index].p_vaddr;
        shdr.sh_size = symtab - gnu_hash;
        shdr.sh_flags = SHF_ALLOC;
        shdr.sh_link = dynsym_index;
        shdr.sh_info = 0;
        shdr.sh_addralign = 8;
        shdr.sh_entsize = 0;

        if (write(out, &shdr, sizeof(shdr)) != sizeof(shdr)) die("Error .gnu.hash");
        ehdr->e_shnum++;
        printf("\t.gnu.hash\n");
    }


    /******************************************/
    /* Ok all sections recovered, now fix GOT */
    /******************************************/
    if(bindnow)
    {
        printf("[*] FULL Relro binary, no GOT reconstruction is needed\n");
        goto section_rebuild_end;
    }
    else if(got_entries == 0)
    {
        printf("[*] WARNING Can't recover GOT entries\n");
        goto section_rebuild_end;
    }
    printf("\n[*] %ld GOT entries found\n", got_entries);

    /* GOT[0] untouched, GOT[1] = 0, GOT[2] = 0 */
    uint64_t got_off = phdr[data_seg_index].p_offset +
                (pltgot - phdr[data_seg_index].p_vaddr);
    uint64_t got_entry = 0x0;

    for (i = 1; i < 3; i++)
    {
        if (lseek(out,
                  got_off + sizeof(Elf64_Addr) * i,
                  SEEK_SET) < 0) 
            die("Seek error");
        
        if (write(out, &got_entry, sizeof(Elf64_Addr)) != sizeof(Elf64_Addr))
            die("Write error");
    }

    /* Recover GOT sections using the recovered PLT address */
    for(i = 3; i < got_entries; i++)
    {
        if (lseek(out,
                  got_off + sizeof(Elf64_Addr)*i,
                  SEEK_SET) < 0) 
            die("Seek error");
        
        got_entry = plt_addr + 0x16 + 0x10*(i-3);
        if (write(out, &got_entry, sizeof(Elf64_Addr)) != sizeof(Elf64_Addr))
            die("Write error");
    }


section_rebuild_end:
    /* Ok, all section recovered. Now rewrite ELF header with correct number of sections */
    if (lseek(out, 0 , SEEK_SET) < 0) 
        die("Seek error");
    if (write(out, (char *)ehdr, sizeof(Elf64_Ehdr)) != sizeof(Elf64_Ehdr)) 
        die("Write error");

    /* Free allocated memory and close files */ 
    for(i=0; i<ehdr->e_phnum; i++)
    {
        free(seg_data[i]);
    }
    free(seg_data);
    close(in);
    close(out);

    return 0;
}


void die(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}


char *xget(int fd, int off, size_t sz)
{
    char *buf;

    if (lseek(fd, off, SEEK_SET) < 0) die("Seek error");
    buf = (char *)malloc(sz);
    if(buf == NULL) die("Malloc error");
    if(read(fd, buf, sz) != sz) die("Read error");
    return buf;
}


char* seg_type_to_str(Elf64_Word type)
{
    switch(type)
    {
        case PT_NULL :          return "NULL";
        case PT_LOAD :          return "LOAD";
        case PT_DYNAMIC:        return "DYNAMIC"; 
        case PT_INTERP:         return "INTERP";
        case PT_NOTE:           return "NOTE";
        case PT_SHLIB:          return "SHLIB"; 
        case PT_PHDR:           return "PHDR";
        case PT_TLS:            return "TLS";
        case PT_LOOS:           return "LOOS"; 
        case PT_HIOS:           return "HIOS"; 
        case PT_LOPROC:         return "LOPROC"; 
        case PT_HIPROC:         return "HIPROC"; 
        case PT_GNU_EH_FRAME:   return "GNU_EH_FRAME"; 
        case PT_GNU_STACK:      return "GNU_STACK"; 
        case PT_GNU_RELRO:      return "GNU_RELRO"; 

        default: return "UNDEFINED";
    }
}


int sec_index(char *sec_name)
{
    int pos = 0;
    int len = 0;

    for (pos = 0; pos < sizeof(shstr);) 
    {
        if(strcmp(sec_name, &shstr[pos]) == 0) 
        {
            return pos;
        }   
        else 
        {
            len = strlen(&shstr[pos]);
            pos += len+1;
        }   
    }   
    return 0;
}
