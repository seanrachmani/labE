#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <elf.h>

//part0
//not allowed to use read,fread

//menu technique as in lab1
struct fun_desc {
char *name;
char index;
char (*fun)(void);
};




//debug as in lab 4
int debug_mode = 0;
void toggle_debug_mode() {
    if(debug_mode == 0) { 
        debug_mode = 1;
        fprintf(stderr, "Debug flag now on\n");
    }
    else{
        debug_mode = 0;
        fprintf(stderr, "Debug flag now off\n");
    }
}


//global vars for examine elf
int num_files = 0;  //which file are we working between the 2
int current_fd[2] = {-1, -1}; 
void *map_start[2] = {NULL, NULL}; //pointers to mapped data
off_t file_sizes[2] = {0, 0};
char file_names[2][100];

void examine_elf() {
    if (num_files >= 2) {
        printf("Error: Maximum number of files (2) already opened.\n");
        return;
    }


    //1)Examine ELF Files queries the user for an ELF file name(s) to be used and examined henceforth. 
    printf("Enter file name: ");
    char filename[100];
    scanf("%s", filename);
    while(getchar() != '\n');

    /*
    In Examine ELF File, after getting a file name, open the file for reading, and then print the following:
    */
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open file");
        return;
    }
    //in order to use mmap we need to have file size
    //struct stat is linux default with st_size feature
    struct stat fd_stat;
    //fstat aka "take fd and put info in struct we defined above"
    if (fstat(fd, &fd_stat) != 0) {
        perror("stat failed");
        close(fd);
        return;
    }





//saving map details for cuurent file then saving it in arrays 
    //st.size is stat struct feature
    int size = fd_stat.st_size;

    //map file to mem
    /*
    mmap takes fd and size and put the elf file into RAM mem
    null for chhosing where to put it in ram
    front-read aka read only
    map_private aka we wont change actual elf file
    offset 0
    now we have in map start the pointer to all elf data
    */

    void *map = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);/**/
    if (map == MAP_FAILED) {
        perror("mmap failed");
        close(fd);
        return;
    }
    
    //treat the pointer we got and get its *header*
    Elf32_Ehdr *header = (Elf32_Ehdr *)map;/**/



    /*
    1)Bytes 1,2,3 of the magic number (in ASCII). Henceforth, you should check that the magic number
     (including the unprintable byte 0 of the header) is consistent with an ELF file, and refuse to continue if it is not.
    */
    if (header->e_ident[EI_MAG0] != 0x7f ||
        header->e_ident[EI_MAG1] != 'E' ||
        header->e_ident[EI_MAG2] != 'L' ||
        header->e_ident[EI_MAG3] != 'F') {
        
        printf("Error: %s is not a valid ELF file.\n", filename);
        munmap(map, size);
        close(fd);
        current_fd[num_files] = -1;
        return;
    }

    //saving temp info in global vars
    current_fd[num_files] = fd;         
    map_start[num_files] = map;          
    file_sizes[num_files] = size;       
    strcpy(file_names[num_files], filename);


    printf("\nELF Header:\n");

    printf("  Magic:                             %c%c%c\n", 
           header->e_ident[EI_MAG1], header->e_ident[EI_MAG2], header->e_ident[EI_MAG3]);

    printf("  Data:                              ");
    if (header->e_ident[EI_DATA] == ELFDATA2LSB) {
        printf("2's complement, little endian\n");
    } else if (header->e_ident[EI_DATA] == ELFDATA2MSB) {
        printf("2's complement, big endian\n");
    } else {
        printf("Unknown\n");
    }
    printf("  Entry point address:               0x%x\n", header->e_entry);
    printf("  Start of section headers:          %d (bytes into file)\n", header->e_shoff);
    printf("  Number of section headers:         %d\n", header->e_shnum);
    printf("  Size of section headers:           %d (bytes)\n", header->e_shentsize);
    printf("  Start of program headers:          %d (bytes into file)\n", header->e_phoff);
    printf("  Number of program headers:         %d\n", header->e_phnum);
    printf("  Size of program headers:           %d (bytes)\n", header->e_phentsize);

    num_files++;
}




//Quit should unmap and close any mapped or open files, and "exit normally".
void quit() {
    if (debug_mode) {
        printf("Quitting... Cleaning up open files and memory.\n");
    }

    for (int i = 0; i < num_files; i++) {
        if (map_start[i] != NULL) {
            //munmap is for reversing map
            munmap(map_start[i], file_sizes[i]);
        }
        if (current_fd[i] != -1) {
            close(current_fd[i]);
        }
    }
    exit(0); 
}


//part1
/*
For each ELF file already opened by Examine ELF File
 Print Section Names should visit all section headers in the section header table,
  and for each one print its index, name, address, offset, size in bytes, and type *number*. 
 The format for each ELF file should be:
File <ELF-file-name> sections:
[index] section_name section_address section_offset section_size  section_type
[index] section_name section_address section_offset section_size  section_type
[index] section_name section_address section_offset section_size  section_type
*/

 //so there is no file just print an error message and return.
void print_sections(void) {
    if (num_files == 0) {
        printf("Error: No ELF files currently mapped\n");
        return;
    }

    //Note that this is done for all files currently mapped,
    for (int i = 0; i < num_files; i++) {
        printf("File %s sections:\n", file_names[i]);
        
        //map we got from mmap - elf data from global array 
        //mmap give us all elf data, casting of header will make it see obly the first 52 bytes which are the header data
        void *map = map_start[i];
        Elf32_Ehdr *header = (Elf32_Ehdr *)map;
        
        //e_shoff is num of bytes to get to sections table form the start of table?
        //cast map to char in order to perform ptrs arithmetic 
        //shdr is struct for single section in linux
        //sections headrs are array of shdrs 
        Elf32_Shdr *section_headers = (Elf32_Shdr *)((char *)map + header->e_shoff);
        
        //find sections names which stored in shstrtab section 
        //this index says which section number is shstrtab aka sectionsNamesTableSection (haha)
        int shstrndx = header->e_shstrndx; 
        //the adress of section in this index(the d)
        Elf32_Shdr *shstrtab_section = &section_headers[shstrndx]; 
        char *shstrtab = (char *)map + shstrtab_section->sh_offset; 

        
        //In debug mode you should also print the value of the important indices and offsets,
        // such as shstrndx 
        if (debug_mode) {
            fprintf(stderr, "Debug: shstrndx (Section Header String Table Index) = %d\n", shstrndx);
        }
        //print sections data
        printf("[index] Name                 Addr       Off    Size   Type\n");

        //e_shnum aka total num of sections in the elf file
        for (int j = 0; j < header->e_shnum; j++) {
            //& aka from struct to pointer
            Elf32_Shdr *section = &section_headers[j];
            
            //sh_name is the offset for the name of the section 
            //(the num of bytes from the beggining of shstrtab)
            //c treats it as string name
            char *name = shstrtab + section->sh_name;
            
            //section name offsets.
            if (debug_mode) {
                fprintf(stderr, "Debug: Section [%d] name offset = %d\n", j, section->sh_name);
            }
            //use shdr features to print rewuires data: sh_addr etc
            //type is saved as number and in readelf its translated to string but in here its not required
            //- for left allignment
            printf("[%2d]    %-20s %08x %06x %06x   %x\n", j, name, section->sh_addr, section->sh_offset, section->sh_size, section->sh_type);
        }
        printf("\n");
    }
}




//part 2
void print_symbols() {
    //same as part 1. we need names table for printing in which section each symbol.
        if (num_files == 0) {
        printf("Error: No ELF files currently mapped.\n");
        return;
    }
    for (int i = 0; i < num_files; i++) {
        void *map = map_start[i];
        Elf32_Ehdr *header = (Elf32_Ehdr *)map;
        Elf32_Shdr *section_headers = (Elf32_Shdr *)((char *)map + header->e_shoff);
        Elf32_Shdr *shstrtab_section = &section_headers[header->e_shstrndx];
        char *shstrtab = (char *)map + shstrtab_section->sh_offset;


        //iter the sections
        for (int j = 0; j < header->e_shnum; j++) {
            //pointer to 
            Elf32_Shdr *current_section = &section_headers[j];
            
            //dymsym for symbs that solved in runtime like library functions 
            if (current_section->sh_type == SHT_SYMTAB || current_section->sh_type == SHT_DYNSYM) {
                
                if (debug_mode) {
                    fprintf(stderr, "Debug: Symbol table size = %d, number of symbols = %d\n", 
                            current_section->sh_size, current_section->sh_size / current_section->sh_entsize);
                }

                char *symtab_name = shstrtab + current_section->sh_name;
                printf("File %s symbols (from %s):\n", file_names[i], symtab_name);
                printf("[index] Value section index section name         symbol name\n");
                //symtab is array of structs. go to start + offset which takes us to the start of this section
                //sym casting makes it an array of sym structs
                Elf32_Sym *symtab = (Elf32_Sym *)((char *)map + current_section->sh_offset);
                //total size/1 symbol size 
                int num_symbols = current_section->sh_size / current_section->sh_entsize;
                //shstrtab is for sections
                //strtab is for symbols names
                //shlink is index for the section number of symbols name
                //so now this is a ptr to symbols names section:
                Elf32_Shdr *strtab_section = &section_headers[current_section->sh_link];
                //strtab is for all symbols names together
                //and this is a ptr to actual symbols name start.(so we can look symbols name in it) 
                //before the casting we are in a start of section that is sym tables(we can have more than 1 section like this)
                char *strtab = (char *)map + strtab_section->sh_offset;


                //iterate symbols
                for (int k = 0; k < num_symbols; k++) {
                    //ptr to current symbol. symtab[k] is sym struct, with & its pointer
                    Elf32_Sym *sym = &symtab[k];
                    //stname is like offset from the start of syrtab
                    char *sym_name = strtab + sym->st_name;
                    char *sec_name;


                    //sym struct has st_shndx that says which section it belongs, some  sections types are special and doesnt represent actual header in the header nums range.
                    //outside syms  (library functions)
                    if (sym->st_shndx == SHN_UNDEF) {
                        sec_name = "UNDEF";
                    } 
                    //constant sym like end
                    else if (sym->st_shndx == SHN_ABS) {
                        sec_name = "ABS";
                    } 
                    //global vars which we didnt initilize yet like int x;
                    else if (sym->st_shndx == SHN_COMMON) {
                        sec_name = "COMMON";
                    } 
                    else if (sym->st_shndx < header->e_shnum) {
                        //shndx which section this symbol in.
                        //sections headers[index] is symtab 
                        //shname is the offset of symbol name in the sections names table
                        //section headers[index].sh_name is where the exact relevant name is for this symbol's section name.
                        sec_name = shstrtab + section_headers[sym->st_shndx].sh_name;
                    } 
                    else {
                        sec_name = "UNKNOWN";
                    }

                    printf("[%2d] %08x %7d  %-20s %s\n", k, sym->st_value, sym->st_shndx, sec_name, sym_name);
                }
                printf("\n");
            }
        }
    }
}

//par2b
void print_relocations() {
    if (num_files == 0) {
        printf("Error: No ELF files currently mapped.\n");
        return;
    }

    for (int i = 0; i < num_files; i++) {
        //find the sections name table for relocations who represent a whole section:
        void *map = map_start[i];
        Elf32_Ehdr *header = (Elf32_Ehdr *)map;
        Elf32_Shdr *section_headers = (Elf32_Shdr *)((char *)map + header->e_shoff);
        Elf32_Shdr *shstrtab_section = &section_headers[header->e_shstrndx];
        char *shstrtab = (char *)map + shstrtab_section->sh_offset;
        //now we have the sectionsNamesTableSection as string in shstrtab
 
        int found_rels = 0;
        //iterate sections to find relocations section
        for (int j = 0; j < header->e_shnum; j++) {
            Elf32_Shdr *current_section = &section_headers[j];
            if (current_section->sh_type == SHT_REL) {
                found_rels ++;
                char *rel_sec_name = shstrtab + current_section->sh_name;
                int num_relocations = current_section->sh_size / current_section->sh_entsize;


                //if we found rel section save its data and find his symbol table
                Elf32_Rel *relocations = (Elf32_Rel *)((char *)map + current_section->sh_offset);
                ////this is the symbol table section that contains the symbols our relocations refer to:
                Elf32_Shdr *symtab_section = &section_headers[current_section->sh_link];
                //actual symbol table:
                Elf32_Sym *symtab = (Elf32_Sym *)((char *)map + symtab_section->sh_offset);
                //dictionary for the symbol table we just found:
                Elf32_Shdr *strtab_section = &section_headers[symtab_section->sh_link];
                //string for the actual names in the symbol table
                char *strtab = (char *)map + strtab_section->sh_offset;
                //we need this bc in the relocations next loop we can use the index in r_info in order to have sym struct of relevant symbol. 

                if (debug_mode) {
                    int symtab_size = symtab_section->sh_size;
                    int num_symbols = symtab_size / symtab_section->sh_entsize;
                    fprintf(stderr, "Debug: Symbol table size: %d, number of symbols: %d\n", symtab_size, num_symbols);
                }
                printf("File %s relocations:\n", file_names[i]);
                printf("[index] location   related_symbol_name      type\n");
                //iterate relocations in the rel section
                for (int k = 0; k < num_relocations; k++) {
                    Elf32_Rel *rel = &relocations[k];
                    //extract relevant info from r_info:
                    //index in the symbol table
                    int sym_index = ELF32_R_SYM(rel->r_info);
                    int rel_type = ELF32_R_TYPE(rel->r_info);
                    //symbol for current relocation:
                    Elf32_Sym *sym = &symtab[sym_index];
                    char *sym_name = "";
                    //st_name is for where the name of the symbol starts
                    if (sym->st_name != 0) {
                        sym_name = strtab + sym->st_name;
                    } 
                    //if st_name==0 the relocation represent section,
                    //extract the section name:
                    else if (sym->st_shndx < header->e_shnum) {
                        sym_name = shstrtab + section_headers[sym->st_shndx].sh_name;
                    }
                    printf("[%2d]    %08x   %-24s %d\n", k, rel->r_offset, sym_name, rel_type);
                }
                printf("\n");
            }
        }
        if (found_relocs == 0) {
            printf("No relocations\n");
        }
    }
}










void check_files() {
    printf("not implemented yet\n");
}

void merge() {
    printf("not implemented yet\n");
}

    struct fun_desc menu1[] = { 
    { "Toggle <D>ebug Mode", 'D', toggle_debug_mode }, 
    { "Examine ELF <F>ile", 'F', examine_elf }, 
    { "Print Section <N>ames", 'N', print_sections }, 
    { "Print <S>ymbols", 'S', print_symbols }, 
    { "Print <R>elocations", 'R', print_relocations }, 
    { "<C>heck Files for Merge", 'C', check_files }, 
    { "<M>erge ELF Files", 'M', merge }, 
    { "<Q>uit", 'Q', quit },
    { NULL, 0, NULL }
    };




void menu() {
    while(feof(stdin) == 0) { 
        fprintf(stdout, "Choose action:\n");
        int idx = 0;
        while(menu1[idx].fun != NULL) {
            printf("%s\n", menu1[idx].name);
            idx++;
        }
        char buffer[50];
        if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
            break; 
        }
        int isError = 1;
        for(int i = 0; menu1[i].fun != NULL; i++) {
            if(buffer[0] == menu1[i].index) {
                menu1[i].fun();
                isError = 0;
            }
        }
        if(isError == 1) {
            printf("Invalid choice.\n");
        }   
    }      
    exit(0);
}
int main() {
    menu();
    return 0;
}