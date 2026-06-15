#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <elf.h>
//not allowed to use read,fread

//menu technique as in lab1
struct fun_desc {
char *name;
char index;
char (*fun)(char);
};

struct fun_desc menu1[] = { 
    { "Toggle <D>ebug Mode", 'D', toggle_debug_mode }, 
    { "Examine ELF <F>ile", 'F', emamine_elf }, 
    { "Print Section <N>ames", 'N', print_sections }, 
    { "Print <S>ymbols", 'S', print_symbols }, 
    { "Print <R>elocations", 'R', print_relocations }, 
    { "<C>heck Files for Merge", 'C', check_files }, 
    { "<M>erge ELF Files", 'M', merge }, 
    { "<Q>uit", 'Q', quit }, 
    { NULL, 0, NULL } 
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






`//saving map details for cuurent file then saving it in arrays 
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



int main() {
    examine_elf();
    if (map_start != NULL) munmap(map_start, file_size);
    if (current_fd != -1) close(current_fd);
    return 0;
}