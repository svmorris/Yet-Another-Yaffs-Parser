/* typedef struct { */
/*     int type;                // object type (file, dir, symlink, etc.) */
/*     int parent_obj_id;       // parent directory’s object ID */
/*     char name[YAFFS_MAX_NAME_LENGTH + 1]; // object name */
/*     int yst_mode;            // permissions */
/*     int yst_uid; */
/*     int yst_gid; */
/*     int yst_atime; */
/*     int yst_mtime; */
/*     int yst_ctime; */
/*     int file_size;           // only for files */
/*     int equiv_id;            // for hard links */
/*     int alias;               // for symlinks */
/*     ... */
/* } yaffs_obj_header; */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>

#define _POSIX_C_SOURCE 200809L
#define SWAP_ENDIEN false
#define EXTRACTED_FILE_NAME "extracted"

/*
 * This parser uses a pretty messy solution for finding
 * the chunk separators. This is probably because its
 * reverse engineered instead of parsed based on the
 * documentation.
 *
 * To find the chunk delimiters the parser is just matching
 * against n amount of 0xff bytes. In my testing 32 was able
 * to catch all but certain large cryptography binaries like
 * openssl. If your dumpfile is a lot more
 * data dense, you might need a smaller one.
 *
 * NOTE: Make sure the compare len is the same length as the string.
 */
#define COMPARE_LEN 32
#define COMPARE_CONST "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"

struct yaffs_obj_header
{
    int type;      /* type of object */
    int parent_id; /* id of parent directory */
    char *name;    /* pointer to object name */
    int offset;    /* offset in the file */
};


int helper_f_strlen(FILE *fp);
int skip_rest_of_block(FILE* fp);
int skip_to_next_block(FILE* fp);
void helper_print_hex(char *array, size_t len);
void handle_dirs(struct yaffs_obj_header *header);
struct yaffs_obj_header *parse_yaffs_header(FILE *fp);
void parse_file(struct yaffs_obj_header *header, FILE *fp);
int e_fread(void *buffer, size_t size, size_t nmemb, FILE *stream);

int main(int argc, char **argv)
{

    if (argc != 2)
    {
        printf("Usage: %s <dump file>", argv[0]);
        return -1;
    }


    FILE *fp = fopen(argv[1], "rb");
    if (fp == NULL)
    {
        perror("Failed to open file");
        return -2;
    }

    int object_type = 0;
    while (1)
    {
        int n = skip_to_next_block(fp);
        if (n < 0)
        {
            perror("File stream ended");
            fclose(fp);
            return 0;
        }

        unsigned long obj_offset = ftell(fp);
        struct yaffs_obj_header *header = parse_yaffs_header(fp);
        // Something went wrong or not a header
        if (header == NULL)
        {
            // After the file parsing is implemented
            // I should probably crash at this point
            skip_rest_of_block(fp);
            continue;
        }

        switch (header->type)
        {
            case 0:
                printf("Yaffs Unknown object found at offset: 0x%lx\n", obj_offset);
                break;
            case 1:
                printf("File found at offset: 0x%lx \"%s\"\n", obj_offset, header->name);
                parse_file(header, fp);
                break;
            case 2:
                printf("Symlink found at offset: 0x%lx \"%s\"\n", obj_offset, header->name);
                break;
            case 3:
                printf("Directory found at offset: 0x%lx \"%s\"\n", obj_offset, header->name);
                handle_dirs(header);
                break;
            case 4:
                printf("Hard link found at offset: 0x%lx \"%s\"\n", obj_offset, header->name);
                break;
            case 5:
                printf("Special filesystem object found at offset: 0x%lx \"%s\"\n", obj_offset, header->name);
                break;
            default:
                fprintf(stderr, "Ignoring unknown object type 0x%x at offset: 0x%lx\n", object_type, obj_offset);
                break;
        }
    }
    fclose(fp);
    return 0;
}

/*
 * Since actually re-creating the filesystem tree is impossible
 * with the data in a raw dump, this just creates the main folder.
 */
void handle_dirs(struct yaffs_obj_header *header)
{
    if (strcmp(header->name, "yaffs_root") == 0)
        if (mkdir("extracted", 0755) == -1)
        {
            perror("Extraction failed");
            exit(-1);
        }
}

/*
 * Extract files from the data dump.
 */
void parse_file(struct yaffs_obj_header *header, FILE *fp)
{
    skip_to_next_block(fp);

    unsigned long backup_offset = ftell(fp);
    size_t file_size = skip_rest_of_block(fp);
    if (file_size < 1)
    {
        fprintf(stderr, "File at offset 0x%x has no data.", header->offset);
        return;
    }

    fseek(fp, backup_offset, SEEK_SET);

    // TODO: check for colliding filenames

    char *filename = malloc(strlen(header->name) + sizeof(EXTRACTED_FILE_NAME) + 1);
    sprintf(filename, "%s/%s", EXTRACTED_FILE_NAME, header->name);
    FILE *outfile = fopen(filename, "wb");

    char byte = '\0';
    for (int i = 0; i < file_size; i++)
    {
        if (e_fread(&byte, 1, 1, fp) != 1)
        {
            fprintf(stderr, "Error while reading file at offset 0x%x", header->offset);
            fclose(outfile);
            return;
        }

        if (fwrite(&byte, 1, 1, outfile) != 1)
        {
            perror("Error while writing file");
            fclose(outfile);
            return;
        }
    }

    fclose(outfile);
}

/*
 * Parses a yaffs object header
 *
 * Returns the struct yaffs_obj_header
 */
struct yaffs_obj_header *parse_yaffs_header(FILE *fp)
{
    struct yaffs_obj_header *header = malloc(sizeof(struct yaffs_obj_header));
    header->offset = (int)ftell(fp);

    /* printf("Attempting to interpret yaffs header at offset: %lx\n", ftell(fp)); */

    // First int in header is the type
    if (e_fread(&header->type, 4, 1, fp) != 1)
    {
        perror("File stream ended before reading object type");
        return NULL;
    }


    // A header cannot be longer than 5
    // If i got here something is wrong with my code.
    if (header->type > 5)
    {
        /* fprintf(stderr, "Ignoring.. Not a valid yaffs header type at offset: 0x%lx\n", ftell(fp)-4); */
        return NULL;
    }


    // second int in header is the parent id
    if (e_fread(&header->parent_id, 4, 1, fp) != 1)
    {
        perror("File stream ended before reading object parent id");
        return NULL;
    }

    // There are two 0xff bytes before the name starts
    if (fseek(fp, 2, SEEK_CUR) < 0)
    {
        perror("fseek failed while parsing object header");
        return NULL;
    }

    int filename_len = helper_f_strlen(fp);
    if (filename_len < 0)
    {
        fprintf(stderr, "Failed to get filename length at offset: 0x%lx\n", ftell(fp));
        return NULL;
    }
    // If both are true, then this is the root directory
    if (header->parent_id == 1 && filename_len == 0)
    {
        char filename[] = "yaffs_root";
        header->name = malloc(sizeof(filename));
        if (header->name == NULL)
        {
            perror("malloc");
            return NULL;
        }
        memcpy(header->name, filename, sizeof(filename));


        // The official spec says yaffs root should have
        // the parent ID of 1 (which is its own ID). This is
        // annoying to deal with so I'm forcing the ID to
        // be 0 instead.
        header->parent_id = 0;
    }
    // Only the yaffs_root directory should have a 0 filename.
    else if(filename_len == 0)
    {
        fprintf(stderr, "Error: Got empty filename for a non-root directory at offset 0x%lx. Skipping...\n", ftell(fp));
        return NULL;
    }
    else
    {
        header->name = malloc(filename_len+1);

        if (e_fread(header->name, filename_len, 1, fp) != 1)
        {
            perror("File stream ended before reading object parent id");
            return NULL;
        }
        header->name[filename_len] = '\0';
    }

    if (skip_rest_of_block(fp) < 0)
    {
        fprintf(stderr, "Could not find end of block at offset %ld\n", ftell(fp));
        return NULL;
    }

    return header;
}

/*
 * Function reads until the next block of data.
 *
 * Returns values:
 *  Positive int = number of bytes skipped
 *  Negative int = Error or EOF
 */
int skip_to_next_block(FILE* fp)
{
    unsigned char byte = '\xff';
    size_t bytes_skipped = 0;
    while (1)
    {
        if (fread(&byte, 1, 1, fp) != 1)
            return -1;


        if (byte != 0xff)
        {

            // The binary data has 4 null bytes at random locations
            // I'm not sure why they are there, but I'm sure its
            // safe to skip them.
            if (byte == 0)
            {
                char buffer[3] = "";
                fread(&buffer, 3, 1, fp);
                if (memcmp(buffer, "\0\0\0", 3) == 0)
                    continue;
                else
                    fseek(fp, -3, SEEK_CUR);
            }


            // Ignore data chunks less than 16 bytes long.
            // Although in my experience headers are usually
            // at least 256 bytes long, 16 is about as small
            // as one can get before not enough data fits.
            int backup_offset = ftell(fp);
            if (skip_rest_of_block(fp) < 16)
                continue;
            fseek(fp, backup_offset, SEEK_SET);




            // Found next block
            if (fseek(fp, -1, SEEK_CUR) != 0)
                return -2;
            return bytes_skipped;
        }
        bytes_skipped++;
    }

    return -1;
}


/*
 * Skip to the end of a block
 *
 * Returns:
 *  Positive integer = number of bytes skipped
 *  negative integer = error
 */
int skip_rest_of_block(FILE* fp)
{
    char bytes[COMPARE_LEN] = "";
    unsigned long offset = ftell(fp);
    unsigned long original_offset = ftell(fp);
    while (1)
    {
        if (e_fread(&bytes, COMPARE_LEN, 1, fp) != 1)
        {
            perror("Fread error while skipping block");
            return -1;
        }

        // This was originally 5, but apparently that many 0xff bytes are not
        // uncommon in gifs. This is not a perfect solution, but if it breaks
        // with new files just add more to it. (and everywhere else you see "10")
        if (memcmp(bytes, COMPARE_CONST, COMPARE_LEN) == 0)
        {
            fseek(fp, -COMPARE_LEN, SEEK_CUR);
            /* printf("Skipped to end of block at: 0x%lx\n", ftell(fp)); */
            return offset - original_offset;
        }

        fseek(fp, ++offset, SEEK_SET);
    }
}

/*
 * A simple function so I don't keep having
 * to make loops to print hex data.
 */
void helper_print_hex(char *array, size_t len)
{
    for (int i = 0; i < len; i++)
        printf("%x ", (unsigned int)array[i]);
}

/*
 * Swap bytes in place
 */
static void helper_swap_endian(void *data, size_t size) {
    unsigned char *bytes = (unsigned char *)data;
    for (size_t i = 0; i < size / 2; i++) {
        unsigned char tmp = bytes[i];
        bytes[i] = bytes[size - 1 - i];
        bytes[size - 1 - i] = tmp;
    }
}

/*
 * Fread wrapper that respects byte-orders.
 *
 * Function should act identical to the normal
 * fread, but swap byte order based on the SWAP_ENDIEN
 * variable.
 *
 * NOTE: I've never properly tested this function
 *       as I realised after writing that I don't
 *       need it in my use case.
 */
int e_fread(void *buffer, size_t size, size_t nmemb, FILE *stream) {
    size_t nread = fread(buffer, size, nmemb, stream);
    if (nread == 0)
    {
        perror("fread didn't read any data");
        return -1;
    }

    if (SWAP_ENDIEN) {
        // Swap each element's byte order
        unsigned char *ptr = (unsigned char *)buffer;
        for (size_t i = 0; i < nread; i++) {
            helper_swap_endian(ptr + i * size, size);
        }
    }

    return (int)nread;
}



/*
 * Gets the length of a string (num bytes to first null or FF)
 * directly from a file stream without changing the file pointer
 * location.
 *
 * Returns:
 *  number of bytes till first null or FF
 *  Negative int for errors
 */
int helper_f_strlen(FILE *fp)
{
    unsigned char byte = '\0';
    int count = 0;
    int backup_offset = ftell(fp);
    int ff_counter = 0;
    while (1)
    {
        if (fread(&byte, 1, 1, fp) != 1)
        {
            perror("Error while getting string len");
            return -1;
        }
        if (byte == 0)
            break;

        // This might just be an issue with my firmware dump
        // but occasionally there are files where the parent_id
        // is one byte longer than it should be. In this case
        // a single ff gets added to the beginning of the name.
        //
        // I think this is just a corruption in my dump,
        // but it should not break the parsing of normal yaffs.
        if (byte == 0xff && ff_counter == 0)
            continue;
        else if (byte == 0xff)
            break;

        count++;
    }
    fseek(fp, backup_offset, SEEK_SET);
    return count;
}
