#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#define h_addr h_addr_list[0]

#define PORT 443

void download_url(char *SERVER, char *PATH);
FILE *formatchecker(FILE *fp);
FILE *parse(FILE *, char);

int main(int argc, char *argv[])
{
    printf("URL path (eg. https://www.example.com/image.jpg):  ");
    char *domain = malloc(1024);
    char *path = malloc(1024);
    char *link = malloc(1024);
    if (domain == NULL)
    {
        exit(2);
    }
    if (path == NULL)
    {
        exit(2);
    }

    scanf("%s", link);
    if (sscanf(link, "https://%[^/]%s", domain, path) == 0)
    {
        printf("Invalid Link Format.");
    }

    printf("domain :<%s>\npath :<%s>\n", domain, path);
    download_url(domain, path);
    FILE *httpsresponse = fopen("response.txt", "rb");
    if (!httpsresponse)
    {
        exit(3);
    }
    fclose(formatchecker(httpsresponse));

    free(link);
    free(domain);
    free(path);
}

void download_url(char *SERVER, char *PATH)
{

    int sockfd;
    struct sockaddr_in serv_addr;
    struct hostent *server;

    SSL_library_init();
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

    if (ctx == NULL)
    {
        printf("Error creating SSL context\n");
    }

    SSL *ssl = SSL_new(ctx);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0)
    {
        printf("Error opening socket\n");
    }

    server = gethostbyname(SERVER);

    if (server == NULL)
    {
        printf("Error resolving server hostname\n");
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("Error connecting to server\n");
    }

    BIO *sbio = BIO_new_socket(sockfd, BIO_NOCLOSE);
    SSL_set_bio(ssl, sbio, sbio);
    if (SSL_set_tlsext_host_name(ssl, SERVER) != 1)
    {
        printf("Error setting SNI\n");
    }
    if (SSL_connect(ssl) <= 0)
    {
        printf("Error establishing SSL connection\n");
    }

    char request[1024];
    sprintf(request, "GET %s HTTP/1.0\r\nHost: %s\r\n\r\n", PATH, SERVER);
    SSL_write(ssl, request, strlen(request));

    char response[1024];
    int bytes_read;
    int total_bytes_read = 0;
    FILE *fp = fopen("response.txt", "wb");

    if (fp == NULL)
    {
        printf("Error opening file\n");
    }

    do
    {
        bytes_read = SSL_read(ssl, response, sizeof(response));
        printf("reading %i", bytes_read);

        if (bytes_read > 0)
        {
            printf("bytes read: %i\n", bytes_read);
            fwrite(response, 1, bytes_read, fp);
            total_bytes_read += bytes_read;
        }
    } while (bytes_read > 0);

    fclose(fp);

    printf("Total bytes read: %d\n", total_bytes_read);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sockfd);
}

// Checking the format and extracting the image file.
FILE *formatchecker(FILE *fp)
{
    int filesize, max;
    char tmpbyte;
    fseek(fp, 0L, SEEK_END);
    filesize = ftell(fp);
    fseek(fp, 0L, SEEK_SET);
    if (filesize > 3000)
    {
        max = 3000;
        for (int i = 0; i < max; i++)
        {
            fread(&tmpbyte, sizeof(char), 1, fp);
            if (tmpbyte == '\n')
            {
                char doublebyte[2];
                fread(&tmpbyte, sizeof(char), 1, fp);
                fseek(fp, -1L, SEEK_CUR);
                fread(&doublebyte, 2 * sizeof(char), 1, fp);
                fseek(fp, -1L, SEEK_CUR);

                if (memcmp(&doublebyte, "\x42\x4D", 2) == 0)
                {

                    fseek(fp, 0L, SEEK_SET);
                    return parse(fp, 'B');
                }

                else if (memcmp(&tmpbyte, "\x89", 1) == 0)
                {
                    char nextseven[7];
                    fread(nextseven, sizeof(char), 7, fp);
                    if (memcmp(nextseven, "\x50\x4E\x47\x0D\x0A\x1A\x0A", 7) == 0)
                    {
                        fseek(fp, 0L, SEEK_SET);
                        return parse(fp, 'P');
                    }
                    else
                    {
                        fseek(fp, -7L, SEEK_CUR);
                    }
                }

                else if (memcmp(&tmpbyte, "\xFF", 1) == 0)
                {
                    char nexttwo[2];
                    fread(nexttwo, sizeof(char), 2, fp);
                    if (memcmp(nexttwo, "\xD8\xFF", 2) == 0)
                    {
                        fseek(fp, 0L, SEEK_SET);
                        return parse(fp, 'J');
                    }
                    else
                    {
                        fseek(fp, -2L, SEEK_CUR);
                    }
                }
            }
        }
    }
    printf("Invalid Format\n");
    return NULL;
}

FILE *parse(FILE *fp, char format)
{
    FILE *img;
    switch (format)
    {
    case 'B':
        img = fopen("out.bmp", "wb");
        break;
    case 'J':
        img = fopen("out.jpg", "wb");
        break;
    case 'P':
        img = fopen("out.png", "wb");
        break;
    }

    char tmpbyte;
    fseek(fp, 0L, SEEK_END);
    int filesize = ftell(fp);
    fseek(fp, 0L, SEEK_SET);
    int write = 0;
    for (int i = 0; i < filesize; i++)
    {
        fread(&tmpbyte, sizeof(char), 1, fp);
        if (write)
        {
            fwrite(&tmpbyte, sizeof(char), 1, img);
        }
        else
        {
            if (tmpbyte == '\n')
            {
                fread(&tmpbyte, sizeof(char), 1, fp);
                if (tmpbyte == '\r')
                {
                    fread(&tmpbyte, sizeof(char), 1, fp);
                    if (tmpbyte == '\n')
                        write = 1;
                }
            }
        }
    }
    return img;
}