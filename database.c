// COMPILAZIONE:
// gcc database.c -o database -I/opt/homebrew/opt/mysql/include -L/opt/homebrew/opt/mysql/lib -lmysqlclient

#include <mysql/mysql.h>
#include <stdio.h>
#include <string.h>

#define SERVER "localhost"
#define USERNAME "root"
#define PASSWORD "password"


int main()
{
    MYSQL* conn = mysql_init(NULL);
    if (conn == NULL) {
        printf("MySQL initialization failed");
        return 1;
    }

    // connessione con server
    if (mysql_real_connect(conn, SERVER, USERNAME, PASSWORD, NULL, 0, NULL, 0) == NULL) {
        printf("Unable to connect with MySQL server\n");
        mysql_close(conn);
        return 1;
    }

    // creazione database
    if (mysql_query(conn, "CREATE DATABASE IF NOT EXISTS voting_db")) {
        printf("Unable to create 'voting_db' database\n");
        mysql_close(conn);
        return 1;
    }

    if (mysql_select_db(conn, "voting_db")) {
      printf("Unable to selecet 'voting_db' database\n");
      mysql_close(conn);
      return 1;
    }

    // creazione tabella con i campi necessari
    if (mysql_query(conn, "CREATE TABLE votes(id INT AUTO_INCREMENT PRIMARY KEY, bignumber TEXT NOT NULL, encrypted_vote LONGBLOB NOT NULL, digital_signature LONGBLOB NOT NULL, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")) {
        printf("Unable to create 'votes' table in 'voting_db' database\n");
        mysql_close(conn);
        return 1;
    }

    // chiusura connessione
    mysql_close(conn);

    printf("Database created successfully\n");
    return 0;
}
