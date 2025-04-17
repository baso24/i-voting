// COMPILAZIONE:
// gcc client.c -o client -I/opt/homebrew/opt/openssl/include -L/opt/homebrew/opt/openssl/lib -lssl -lcrypto

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <ctype.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#define PORT 8080

// funzione che genera un big number casuale univoco e lo salva su un file in locale da inviare al server
void generate_bignumber_and_save(const char *filename){
    BIGNUM *bn = BN_new();  // creazione di un nuovo numero BIGNUM

    if (!bn) {
        fprintf(stderr, "Errore: impossibile allocare il BIGNUM\n");
        return;
    }

    // generazione di un numero casuale di 1024 bit
    if (!BN_rand(bn, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY)) {
        fprintf(stderr, "Errore: generazione numero casuale fallita\n");
        BN_free(bn);
        return;
    }

    char *bn_dec = BN_bn2dec(bn);  // conversione formato decimale

    if (!bn_dec) {
        fprintf(stderr, "Errore: conversione big number fallita\n");
        BN_free(bn);
        return;
    }

    // scrive il numero su un file
    FILE *file = fopen(filename, "w");
    if (!file) {
        fprintf(stderr, "Errore: impossibile aprire il file %s\n", filename);
        OPENSSL_free(bn_dec);
        BN_free(bn);
        return;
  }

    fprintf(file, "%s", bn_dec);

    // pulizia della memoria
    fclose(file);
    OPENSSL_free(bn_dec);
    BN_free(bn);
}

// funzione che genera un certificato digitale in formato X509 autofirmato
void generate_certificate(const char *private_key_path, const char *public_key_path, const char *cert_path) {
    // apertura chiave privata
    FILE *private_key_file = fopen(private_key_path, "rb");
    if (!private_key_file) {
        perror("Errore nell'apertura del file della chiave privata");
        return;
    }
    EVP_PKEY *private_key = PEM_read_PrivateKey(private_key_file, NULL, NULL, NULL);
    fclose(private_key_file);
    if (!private_key) {
        fprintf(stderr, "Errore nella lettura della chiave privata\n");
        return;
    }

    // apertura chiave pubblica
    FILE *public_key_file = fopen(public_key_path, "rb");
    if (!public_key_file) {
        perror("Errore nell'apertura del file della chiave pubblica");
        EVP_PKEY_free(private_key);
        return;
    }
    EVP_PKEY *public_key = PEM_read_PUBKEY(public_key_file, NULL, NULL, NULL);
    fclose(public_key_file);
    if (!public_key) {
        fprintf(stderr, "Errore nella lettura della chiave pubblica\n");
        EVP_PKEY_free(private_key);
        return;
    }

    // creazione nuovo oggetto X509
    X509 *x509 = X509_new();
    if (!x509) {
        fprintf(stderr, "Errore nella creazione dell'oggetto X509\n");
        EVP_PKEY_free(private_key);
        EVP_PKEY_free(public_key);
        return;
    }

    // versione del certificato (X.509 v3)
    X509_set_version(x509, 2);

    // numero di serie
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    // alidità del certificato (es: valido per un anno)
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

    // chiave pubblica associata al certificato
    X509_set_pubkey(x509, public_key);

    // nome del soggetto e dell'emittente
    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"IT", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"My Organization", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"www.example.com", -1, -1, 0);

    // copia il nome del soggetto come nome dell'emittente (certificato autofirmato)
    X509_set_issuer_name(x509, name);

    // firmi il certificato con la chiave privata
    if (!X509_sign(x509, private_key, EVP_sha256())) {
        fprintf(stderr, "Errore nella firma del certificato\n");
        X509_free(x509);
        EVP_PKEY_free(private_key);
        EVP_PKEY_free(public_key);
        return;
    }

    // scrivo il contenuto del certificato in formato PEM su file in locale
    FILE *cert_file = fopen(cert_path, "wb");
    if (!cert_file) {
        perror("Errore nell'apertura del file del certificato");
        X509_free(x509);
        EVP_PKEY_free(private_key);
        EVP_PKEY_free(public_key);
        return;
    }
    if (!PEM_write_X509(cert_file, x509)) {
        fprintf(stderr, "Errore nella scrittura del certificato\n");
        fclose(cert_file);
        X509_free(x509);
        EVP_PKEY_free(private_key);
        EVP_PKEY_free(public_key);
        return;
    }
    fclose(cert_file);

    X509_free(x509);
    EVP_PKEY_free(private_key);
    EVP_PKEY_free(public_key);
}

// funzione che legge il file da cifrare e ritorna il contenuto
char* read_file(const char* filename, size_t* length){
    FILE *f = fopen(filename, "rb");
    if(f == NULL){
        printf("Errore nell'apertura del file");
        return 0;
    }

    fseek(f, 0, SEEK_END);
    *length = ftell(f);
    fseek(f, 0, SEEK_SET);

    char* content = (char*)malloc(*length+1);
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

// funzione che si occupa prevalentemente della cifratura
unsigned char* rsa_encrypt(EVP_PKEY* evp_pub_key, const unsigned char* data, size_t data_len, size_t* encrypted_len) {
    // creazione contesto con chiave pubblica
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(evp_pub_key, NULL);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // inizializzazione del contesto
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    // setting del padding raccomandato nella documentazione openssl RSA_PKCS1_OAEP_PADDING
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    // determinaro la lunghezza di encrypted_len per sapere la lunghezza del file cifrato
    if (EVP_PKEY_encrypt(ctx, NULL, encrypted_len, data, data_len) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    // definisco encrypted lungo esttamente quanto sarà la lunghezza del file cifrato
    unsigned char* encrypted = (unsigned char*)malloc(*encrypted_len);
    if (!encrypted) {
        perror("Errore allocazione buffer cifrato");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    // cifratura in cui il file cifrato viene salvato all'interno di encrypted
    if (EVP_PKEY_encrypt(ctx, encrypted, encrypted_len, data, data_len) <= 0) {
        ERR_print_errors_fp(stderr);
        free(encrypted);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    // pulizia memoria
    EVP_PKEY_CTX_free(ctx);

    return encrypted;
}

// funzione che scrive il contenuto del file cifrato in un nuovo file
int write_encrypted_file(const char* output_file, const unsigned char* data, size_t data_len){
    FILE *f = fopen(output_file, "wb");
    if(f == NULL){
        printf("Errore nell'apertura del file cifrato");
        return 0;
    }

    fwrite(data, 1, data_len, f);
    fclose(f);

    return 1;
}

// funzione che invia un file di testo generico da client a server
void send_file(int serverSocket, const char *filePath) {
    FILE *file = fopen(filePath, "rb");
    if (file == NULL) {
        perror("Errore nell'aprire il file");
        return;
    }

    char buffer[256];
    size_t bytesRead;

    while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (send(serverSocket, buffer, bytesRead, 0) == -1) {
            perror("Errore nell'invio del file");
            fclose(file);
            return;
        }
    }

    fclose(file);
}

// funzione principale che chiama rsa_encrypt per cifrare il file e write_encrypted_file per salvarlo
void encryption(const char* fileName, const char* public_key, const char* output_file){
    // lettura e salvataggio del in file_content
    size_t file_len;
    char* file_content = read_file(fileName, &file_len);
    if(!file_content) return;

    // apertura chiave pubblica precedentemente generata e salvata in locale
    FILE *pub_key_fp = fopen(public_key, "rb");
    if (!pub_key_fp) {
        perror("Errore nell'apertura del file della chiave pubblica");
        return;
    }

    // salvataggio chiave pubblica (formato .pem)
    EVP_PKEY *evp_pub_key = PEM_read_PUBKEY(pub_key_fp, NULL, NULL, NULL);
    fclose(pub_key_fp);
    if (!evp_pub_key) {
        ERR_print_errors_fp(stderr);
        free(file_content);
        return;
    }

    // chiamata a funzione rsa_encrypt a cui passo chiave pubblica, contenuto del file da cifrare, lunghezza del file da cifrare e lunghezza del file cifrato
    size_t encrypted_len;
    unsigned char* encrypted_content = rsa_encrypt(evp_pub_key, (unsigned char*)file_content, file_len, &encrypted_len);
    if (!encrypted_content) {
        EVP_PKEY_free(evp_pub_key);
        free(file_content);
        return;
    }

    // scrittura del file cifrato in un nuovo file che salvo in locale
    if (!write_encrypted_file(output_file, encrypted_content, encrypted_len)) {
        EVP_PKEY_free(evp_pub_key);
        free(file_content);
        free(encrypted_content);
        return;
    }

    // pulizia memoria
    free(file_content);
    free(encrypted_content);
    EVP_PKEY_free(evp_pub_key);
}

// funzione che si occupa totalmente della firma digitale
void sign_file(const char *input_file, const char *key_file, const char *output_file) {
    // apertura dei file di cui ho bisogno: file da firmare, chiave privata e file di output che conterrà la firma
    FILE *in = fopen(input_file, "rb");
    if (!in) {
        perror("Errore apertura file di input");
        return;
    }

    FILE *key = fopen(key_file, "rb");
    if (!key) {
        perror("Errore apertura file chiave privata");
        fclose(in);
        return;
    }

    FILE *out = fopen(output_file, "wb");
    if (!out) {
        perror("Errore apertura file di output");
        fclose(in);
        fclose(key);
        return;
    }

    // carico la chiave privata nella struttura EVP_PKEY
    EVP_PKEY *pkey = PEM_read_PrivateKey(key, NULL, NULL, NULL);
    if (!pkey) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pkey);
        fclose(in);
        fclose(key);
        fclose(out);
        return;
    }

    // creazione del contesto
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mdctx);
        fclose(in);
        fclose(key);
        fclose(out);
        return;
    }

    // inizializzazione del contesto della firma digitale
    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mdctx);
        fclose(in);
        fclose(key);
        fclose(out);
        return;
    }

    // leggo il file di input e aggiorno l'hash man mano che leggo
    unsigned char buffer[1024];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), in)) > 0) {
        if (EVP_DigestSignUpdate(mdctx, buffer, bytes_read) <= 0) {
            ERR_print_errors_fp(stderr);
            EVP_PKEY_free(pkey);
            EVP_MD_CTX_free(mdctx);
            fclose(in);
            fclose(key);
            fclose(out);
            return;
        }
    }

    // determino la lunghezza di sig_len
    size_t sig_len;
    if (EVP_DigestSignFinal(mdctx, NULL, &sig_len) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mdctx);
        fclose(in);
        fclose(key);
        fclose(out);
        return;
    }

    // definisco sig che conterrà la firma digitale
    unsigned char *sig = malloc(sig_len);
    if (!sig) {
        perror("Errore allocazione memoria");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        fclose(in);
        fclose(key);
        fclose(out);
        return;
    }

    // conclusione firma digitale e salvataggio della firma in sig
    if (EVP_DigestSignFinal(mdctx, sig, &sig_len) <= 0) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        fclose(in);
        fclose(key);
        fclose(out);
        return;
    }

    // scrivo il contenuto di sig (firma digitale) nel file di output che salvo in locale
    if (fwrite(sig, 1, sig_len, out) != sig_len) {
        perror("Errore nella scrittura file di output");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        fclose(in);
        fclose(key);
        fclose(out);
        return;
    }

    // pulizia memoria
    free(sig);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    fclose(in);
    fclose(key);
    fclose(out);
}

int main(int argc, char const* argv[])
{
    // prima parte del main che instaura la connessione client server
    int status, valread, client_fd;
    struct sockaddr_in serv_addr;
    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    if ((status = connect(client_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr))) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }

    //generazione e salvataggio bignumber
    generate_bignumber_and_save("bignumber.txt");

    // cifratura file
    encryption("file.txt", "server_public_key.pem", "file_encrypted.txt");
    encryption("bignumber.txt", "server_public_key.pem", "bignumber_encrypted.txt");

    // firma digitale applicata sul file già cifrato
    sign_file("file_encrypted.txt", "client_private_key.pem", "digest.txt");

    // generazione certificato
    generate_certificate("client_private_key.pem", "client_public_key.pem", "certificate.pem");

    /*
    COMANDI OPENSSL PER RICHIEDERE UN TIMESTAMP ALLA TSA (Time Stamping Authority):

    -->   openssl ts -query -data file_encrypted.txt -no_nonce -sha256 -out vote.tsq

    -->   curl -H "Content-Type: application/timestamp-query" --data-binary @vote.tsq http://localhost:8081 -o vote.tsr


    INVIO DEL FILE vote.tsr AL SERVER PER VERIFICA:

    const char *timerequestPath = "vote.tsr";
    send_file(client_fd, timerequestPath);
    printf("--> The timestamp has been successfully sent\n");

    */

    // invio di tutti i file necessari al server
    const char *filePath = "file_encrypted.txt";
    send_file(client_fd, filePath);
    printf("--> The encrypted file has been successfully sent\n");

    const char *bignumberPath = "bignumber_encrypted.txt";
    send_file(client_fd, bignumberPath);
    printf("--> The encrypted big number has been successfully sent\n");

    const char *digestPath = "digest.txt";
    send_file(client_fd, digestPath);
    printf("--> The digital signature on the encrypted file has been successfully sent\n");

    const char *certPath = "certificate.pem";
    send_file(client_fd, certPath);
    printf("--> The self-signed X509 certificate has been successfully sent\n");

    // chiusura connessione
    close(client_fd);
    return 0;
}
