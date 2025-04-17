// COMPILAZIONE:
// gcc counting.c -o counting -I/opt/homebrew/opt/openssl/include -I/opt/homebrew/opt/mysql/include -L/opt/homebrew/opt/openssl/lib -L/opt/homebrew/opt/mysql/lib -lssl -lcrypto -lmysqlclient

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <mysql/mysql.h>
#define SERVER "localhost"
#define USERNAME "root"
#define PASSWORD "password"

// funzione che legge il file e ritorna il contenuto
unsigned char* read_file(const char *filename, size_t* length){
    FILE *f = fopen(filename, "rb");
    if(f == NULL){
        printf("Errore nell'apertura del file cifrato");
        return 0;
    }

    fseek(f, 0, SEEK_END);
    *length = ftell(f);
    rewind(f);

    unsigned char* content = (unsigned char*)malloc(*length+1);
    if(!content){
        printf("Errore allocazione memoria\n");
        fclose(f);
        return NULL;
    }

    fread(content, 1, *length, f);
    fclose(f);
    content[*length] = '\0';

    return content;
}

// funzione che scrive dati su un nuovo file che viene salvato in locale
int write_file(const char *filename, const unsigned char *data, size_t size) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("Errore nell'apertura del file");
        return 0;
    }

    fwrite(data, 1, size, file);
    fclose(file);
    return 1;
}

// funzione per recuperare i file dal database
void retrieve_vote_from_db() {
    MYSQL *conn = mysql_init(NULL);
    if (!conn) {
        fprintf(stderr, "Errore inizializzazione MySQL\n");
        return;
    }

    if (mysql_real_connect(conn, SERVER, USERNAME, PASSWORD, "voting_db", 0, NULL, 0) == NULL) {
        fprintf(stderr, "Errore connessione al database: %s\n", mysql_error(conn));
        mysql_close(conn);
        return;
    }

    // query per cancellare tutte le firme digitali presenti nel database
    const char *delete_query = "UPDATE votes SET digital_signature = NULL";
    if (mysql_query(conn, delete_query)) {
        fprintf(stderr, "Errore eliminazione digital_signature: %s\n", mysql_error(conn));
    } else {
        printf("--> Tutte le firme digitali sono state rimosse dal database!\n");
    }

    // query per ottenere i dati, li ordino in modo randomico per simulare il mixing
    MYSQL_STMT *stmt = mysql_stmt_init(conn);
    const char *query = "SELECT encrypted_vote FROM votes ORDER BY RAND()";

    if (mysql_stmt_prepare(stmt, query, strlen(query))) {
        fprintf(stderr, "Errore preparazione query: %s\n", mysql_error(conn));
        mysql_stmt_close(stmt);
        mysql_close(conn);
        return;
    }

    if (mysql_stmt_execute(stmt)) {
       fprintf(stderr, "Errore esecuzione query: %s\n", mysql_stmt_error(stmt));
       mysql_stmt_close(stmt);
       mysql_close(conn);
       return;
    }

    MYSQL_BIND bind[1];
    memset(bind, 0, sizeof(bind));
    unsigned char encrypted_file_data[5000]; // massima dimensione ipotetica del file binario
    unsigned long encrypted_file_size;

    bind[0].buffer_type = MYSQL_TYPE_BLOB;
    bind[0].buffer = encrypted_file_data;
    bind[0].buffer_length = sizeof(encrypted_file_data);
    bind[0].length = &encrypted_file_size;

    mysql_stmt_bind_result(stmt, bind);

    // salvo tutti i voti con nomi casuali per aumentare la randomicità
    srand(time(NULL));
    while (mysql_stmt_fetch(stmt) == 0) {
        char filename[50];
        snprintf(filename, sizeof(filename), "retrieved_encrypted_file_%d.txt", rand());
        write_file(filename, encrypted_file_data, encrypted_file_size);
    }

    printf("--> Encrypted votes from database saved successfully\n");

    mysql_stmt_close(stmt);
    mysql_close(conn);
}

// funzione che si occupa di tutto il processo di decifratura del file arrivato dal client
int decrypt_file(const char *encrypted_file, const char *private_key_file, const char *output_file) {
    // determino lunghezza del file cifrato
    size_t encrypted_size;
    unsigned char *encrypted_data = read_file(encrypted_file, &encrypted_size);
    if (!encrypted_data) {
        return 0;
    }

    // apertura chiave privata del server
    FILE *server_private_key_file = fopen("server_private_key.pem", "rb");
    if (!server_private_key_file) {
        perror("Errore nell'apertura del file della chiave privata");
        free(encrypted_data);
        return 0;
    }

    // salvataggio chiave privata nella struttura EVP_PKEY
    EVP_PKEY *private_key = PEM_read_PrivateKey(server_private_key_file, NULL, NULL, NULL);
    fclose(server_private_key_file);
    if (!private_key) {
        fprintf(stderr, "Errore nella lettura della chiave privata: %s\n", ERR_error_string(ERR_get_error(), NULL));
        free(encrypted_data);
        return 0;
    }

    // creazione del contesto di decifratura
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(private_key, NULL);
    if (!ctx) {
        fprintf(stderr, "Errore nella creazione del contesto EVP: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_PKEY_free(private_key);
        free(encrypted_data);
        return 0;
    }

    // inizializzazione del contesto di decifratura
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        fprintf(stderr, "Errore nell'inizializzazione della decifratura: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(private_key);
        free(encrypted_data);
        return 0;
    }

    // setting del padding RSA coincidente con quello settato nel client
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        fprintf(stderr, "Errore nella configurazione del padding: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(private_key);
        free(encrypted_data);
        return 0;
    }

    // determino quanto sarà la lunghezza del contenuto decifrato
    size_t decrypted_size;
    if (EVP_PKEY_decrypt(ctx, NULL, &decrypted_size, encrypted_data, encrypted_size) <= 0) {
        fprintf(stderr, "Errore nel calcolo della dimensione decifrata: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(private_key);
        free(encrypted_data);
        return 0;
    }

    // definisco decrypted_data lungo quanto sarà la lunghezza del contenuto decifrato
    unsigned char *decrypted_data = (unsigned char*)malloc(decrypted_size);
    if (!decrypted_data) {
        perror("Errore allocazione memoria per il buffer decifrato");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(private_key);
        free(encrypted_data);
        return 0;
    }

    // decifratura
    if (EVP_PKEY_decrypt(ctx, decrypted_data, &decrypted_size, encrypted_data, encrypted_size) <= 0) {
        fprintf(stderr, "Errore nella decifratura: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(private_key);
        free(encrypted_data);
        free(decrypted_data);
        return 0;
    }

    // scrivo il contenuto della decifratura (decrypted_data) in un nuovo file
    if (!write_file(output_file, decrypted_data, decrypted_size)) {
        fprintf(stderr, "Errore nella scrittura del file decifrato\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(private_key);
        free(encrypted_data);
        free(decrypted_data);
        return 0;
    }

    printf("--> File successfully decrypted and saved in: %s\n", output_file);

    // pulizia memoria
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(private_key);
    free(encrypted_data);
    free(decrypted_data);
    return 1;
}

int main()
{
    // recupero il file e lo salvo in locale
    retrieve_vote_from_db();

    // decifro il file con la chiave privata del server e salvo il contenuto cifrato in received_decrypted_file.txt
    if (!decrypt_file("retrieved_encrypted_file.txt", "server_private_key.pem", "retrieved_decrypted_file.txt")) {
        fprintf(stderr, "Errore durante la decifratura del file.\n");
        return -1;
    }

}
