// COMPILAZIONE:
// gcc server.c -o server -I/opt/homebrew/opt/openssl/include -I/opt/homebrew/opt/mysql/include -L/opt/homebrew/opt/openssl/lib -L/opt/homebrew/opt/mysql/lib -lssl -lcrypto -lmysqlclient

#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <mysql/mysql.h>
#define SERVER "localhost"
#define USERNAME "root"
#define PASSWORD "password"
#define PORT 8080

// funzione che riceve il file dal client e lo salva in locale in un nuovo file
void receiveFile(int clientSocket, const char *fileName) {
    FILE *file = fopen(fileName, "wb");
    if (file == NULL) {
        perror("Errore nell'aprire il file per la scrittura");
        return;
    }

    char buffer[256]; //dimensione buffer
    ssize_t bytesReceived;

    printf("--> Receiving file: %s...\n", fileName);
    while ((bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0)) > 0) {
        fwrite(buffer, 1, bytesReceived, file);
        if (bytesReceived <= sizeof(buffer)) break;
    }

    if (bytesReceived == -1) {
        perror("Errore durante la ricezione del file");
    }

    fclose(file);
}

// funzione che riceve il file dal client e lo salva in locale in un nuovo file (versione big con buffer più grande)
void receiveBigFile(int clientSocket, const char *fileName) {
    FILE *file = fopen(fileName, "wb");
    if (file == NULL) {
        perror("Errore nell'aprire il file per la scrittura");
        return;
    }

    char buffer[4096]; //dimensione buffer più grande
    ssize_t bytesReceived;

    printf("--> Receiving file: %s...\n", fileName);
    while ((bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0)) > 0) {
        fwrite(buffer, 1, bytesReceived, file);
        if (bytesReceived <= sizeof(buffer)) break;
    }

    if (bytesReceived == -1) {
        perror("Errore durante la ricezione del file");
    }

    fclose(file);
}

// funione che scrive dati su un nuovo file che viene salvato in locale
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

// funzione che si occupa della verifica della firma digitale
int verify_signature(const char *file_path, const char *public_key_path, const char *signature_path) {
    // apertura file decifrato
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        perror("Errore nell'apertura del file");
        return 0;
    }

    // apertura file chiave pubblica del client
    FILE *key_file = fopen(public_key_path, "rb");
    if (!key_file) {
        perror("Errore nell'apertura della chiave pubblica");
        fclose(file);
        return 0;
    }

    // salvataggio chiave pubblica del client nella struttura EVP_PKEY
    EVP_PKEY *public_key = PEM_read_PUBKEY(key_file, NULL, NULL, NULL);
    fclose(key_file);
    if (!public_key) {
        ERR_print_errors_fp(stderr);
        fclose(file);
        return 0;
    }

    // apertura file che contiene la firma digitale inviata dal client
    FILE *sig_file = fopen(signature_path, "rb");
    if (!sig_file) {
        perror("Errore nell'apertura del file di firma");
        fclose(file);
        EVP_PKEY_free(public_key);
        return 0;
    }

    // determino lunghezza della firma digitale
    fseek(sig_file, 0, SEEK_END);
    size_t sig_len = ftell(sig_file);
    rewind(sig_file);

    // definisco sig grande quanto è lunga la firma digitale
    unsigned char *sig = malloc(sig_len);
    if (!sig) {
        perror("Errore di allocazione memoria per la firma");
        EVP_PKEY_free(public_key);
        fclose(file);
        fclose(sig_file);
        return 0;
    }

    // leggo la firma, salvo il contenuto in sig e chiudo il file
    fread(sig, 1, sig_len, sig_file);
    fclose(sig_file);

    // creazione contesto
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(public_key);
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        free(sig);
        return 0;
    }

    // inizializzazione contesto di verifica di firma digitale in cui passo la chiave pubblica del client
    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, public_key) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(public_key);
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        free(sig);
        return 0;
    }

    // leggo il file decifrato e aggiorno il contesto
    unsigned char buffer[1024];
    size_t len;
    while ((len = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (EVP_DigestVerifyUpdate(mdctx, buffer, len) <= 0) {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_free(public_key);
            EVP_MD_CTX_free(mdctx);
            fclose(file);
            free(sig);
            return 0;
        }
    }

    fclose(file);

    // avendo "inserito" nel contesto la firma digitale ricevuta, la chiave pubblica del client e il file decifrato
    // dispongo di tutti gli strumenti per verificare la firma digitale tramite EVP_DigestVerifyFinal

    // verifica finale che controlla se la firma digitale è valida
    int verify = EVP_DigestVerifyFinal(mdctx, sig, sig_len);
    if (verify == 1) {
        free(sig);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(public_key);
        return 1;
    } else if (verify == 0) {
        free(sig);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(public_key);
        return 0;
    } else {
        free(sig);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(public_key);
        return 0;
    }

}

// funzione che si occupa del salvataggio dei file nel database
void save_to_database(const char *decrypted_bignumber_file, const char *encrypted_file, const char *signature_file){
    MYSQL *conn = mysql_init(NULL);
    if (!conn) {
        fprintf(stderr, "Errore inizializzazione MySQL\n");
        return;
    }

    // connessione al database
    if (mysql_real_connect(conn, SERVER, USERNAME, PASSWORD, "voting_db", 0, NULL, 0) == NULL) {
        fprintf(stderr, "Errore connessione al database: %s\n", mysql_error(conn));
        mysql_close(conn);
        return;
    }

    // lettura file binari
    size_t encrypted_file_size, signature_file_size;
    unsigned char *encrypted_file_data = read_file(encrypted_file, &encrypted_file_size);
    unsigned char *signature_file_data = read_file(signature_file, &signature_file_size);

    // lettura file bignumber
    size_t decrypted_bignumber_size;
    unsigned char *decrypted_bignumber_data = read_file(decrypted_bignumber_file, &decrypted_bignumber_size);

    if (!encrypted_file_data || !signature_file_data || !decrypted_bignumber_data) {
        fprintf(stderr, "Errore lettura file\n");
        mysql_close(conn);
        return;
    }

    // query SQL preparata per maggiore sicurezza
    MYSQL_STMT *stmt = mysql_stmt_init(conn);
    const char *query = "INSERT INTO votes (bignumber, encrypted_vote, digital_signature) VALUES (?, ?, ?)";

    if (mysql_stmt_prepare(stmt, query, strlen(query))) {
        fprintf(stderr, "Errore preparazione query: %s\n", mysql_error(conn));
        free(encrypted_file_data);
        free(signature_file_data);
        mysql_stmt_close(stmt);
        mysql_close(conn);
        return;
    }

    // associazioni del bignumber e dei dati binari da inserire nel database
    MYSQL_BIND bind[3];
    memset(bind, 0, sizeof(bind));

    bind[0].buffer_type = MYSQL_TYPE_STRING;
    bind[0].buffer = decrypted_bignumber_data;
    bind[0].buffer_length = decrypted_bignumber_size;
    bind[0].is_null = 0;

    bind[1].buffer_type = MYSQL_TYPE_BLOB;
    bind[1].buffer = encrypted_file_data;
    bind[1].buffer_length = encrypted_file_size;
    bind[1].is_null = 0;

    bind[2].buffer_type = MYSQL_TYPE_BLOB;
    bind[2].buffer = signature_file_data;
    bind[2].buffer_length = signature_file_size;
    bind[2].is_null = 0;

    mysql_stmt_bind_param(stmt, bind);

    // esecuzione query
    if (mysql_stmt_execute(stmt)) {
        printf("--> Vote successfully stored in database\n");
    } else {
        fprintf(stderr, "Errore inserimento dati: %s\n", mysql_stmt_error(stmt));
    }

    // pulizia memoria
    free(decrypted_bignumber_data);
    free(encrypted_file_data);
    free(signature_file_data);
    mysql_stmt_close(stmt);
    mysql_close(conn);
}

int main(int argc, char const* argv[])
{
    // prima parte del main che si occupa di instaurare la connessione con il client
    int server_fd, new_socket;
    ssize_t valread;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    if ((new_socket = accept(server_fd, (struct sockaddr*)&address, &addrlen)) < 0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    // ricevo e salvo in locale il file cifrato, la firma digitale e il certificato ricevuti dal client
    receiveFile(new_socket, "received_encrypted_file.txt");
    receiveFile(new_socket, "received_encrypted_bignumber.txt");
    receiveFile(new_socket, "received_digest.txt");
    receiveBigFile(new_socket, "received_certificate.pem");


    /*
    FUNZIONE PER RICEVERE IL FILE CONTENENTE IL TIMESTAMP:

    receiveFile(new_socket, "received_vote.tsr")


    COMANDI OPENSSL PER VERIFICARE SE IL TIMESTAMP E' VALIDO E PER ASSICURARCI CHE IL CERTIFICATO RILASCIATO DALLA TSA NON SIA STATO REVOCATO:

    -->   openssl ts -verify -in received_vote.tsr -CAfile tsa_cert.pem

    -->   openssl ocsp -issuer tsa_issuer.pem -cert tsa_cert.pem -url http://ocsp.server.com -resp_text -CAfile rootCA.pem

    SE TUTTO VIENE VERIFICATO CORRETTAMENTE SI PUO' PROCEDERE CON LA MEMORIZZAZIONE DEL VOTO

    */

    // verifica della firma digitale sul file ricevuto ancora cifrato
    // se la firma è valida, il file del voto criptato e il file della firma digitale vengono salvati nel database insieme al timestamp
    if (verify_signature("received_encrypted_file.txt", "client_public_key.pem", "received_digest.txt")){
        printf("--> Digital signature successfully verified\n");
        // decifro il bignumber con la chiave privata del server e salvo il contenuto cifrato in received_decrypted_bignumber.txt perchè voglio inserirlo nel database decifrato
        if (!decrypt_file("received_encrypted_bignumber.txt", "server_private_key.pem", "received_decrypted_bignumber.txt")) {
            fprintf(stderr, "Errore durante la decifratura del file.\n");
            return -1;
        }
        save_to_database("received_decrypted_bignumber.txt", "received_encrypted_file.txt", "received_digest.txt");
    } else {
        printf("--> Digital signature NOT successfully verified\n");
    }

    // chiusura connessione
    close(new_socket);
    close(server_fd);
    return 0;
}
