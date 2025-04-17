// COMPILAZIONE:
// gcc server_gen_keys.c -o server_gen_keys -I/opt/homebrew/opt/openssl/include -L/opt/homebrew/opt/openssl/lib -lssl -lcrypto

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>

int main() {
    // dimensione chiave e esponente pubblico
    int key_length = 2048;
    unsigned long e = RSA_F4; //(RSA_F4 = 65537)

    // generazione della struttura per la chiave RSA
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    BN_set_word(bn, e);

    // generazione della chiave RSA
    if (RSA_generate_key_ex(rsa, key_length, bn, NULL) != 1) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // salvataggio della chiave privata su file
    FILE *private_file = fopen("server_private_key.pem", "wb");
    if (!private_file) {
        perror("Errore nell'apertura del file per la chiave privata");
        RSA_free(rsa);
        BN_free(bn);
        return 1;
    }
    PEM_write_RSAPrivateKey(private_file, rsa, NULL, NULL, 0, NULL, NULL);
    fclose(private_file);

    // salvataggio della chiave pubblica su file
    FILE *public_file = fopen("server_public_key.pem", "wb");
    if (!public_file) {
        perror("Errore nell'apertura del file per la chiave pubblica");
        RSA_free(rsa);
        BN_free(bn);
        return 1;
    }
    PEM_write_RSA_PUBKEY(public_file, rsa);
    fclose(public_file);

    // pulizia della memoria
    RSA_free(rsa);
    BN_free(bn);

    printf("Coppia di chiavi generata e salvata nei file 'server_private_key.pem' e 'server_public_key.pem'.\n");
    return 0;
}
