# i-voting
Client-server architecture that simulates the secure sending of a vote (i-vote), its storage, anonymization and counting through the use of various scripts written in C language that make extensive use of the OpenSSL library.

It is necessary to preliminarily execute the two codes for the generation of the RSA keys on the client and server side and the database.c code for the creation of the database if there is not one.

Subsequently, given the vote contained in file.txt, the client-server communication can be started (the loopback address is used).

once the communication is finished, the vote has been stored in the mysql database.

Finally, we can execute the counting.c script for the anonymization and counting of the votes present in the database.
