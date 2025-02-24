#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include <time.h>
#include <openssl/sha.h>
#include <stdbool.h>

#define MAX_TITLE_LENGTH 100
#define MAX_COMPANY_LENGTH 100
#define MAX_LOCATION_LENGTH 100
#define MAX_DESCRIPTION_LENGTH 1000
#define HASH_LENGTH 64

typedef struct {
    char title[MAX_TITLE_LENGTH];
    char company[MAX_COMPANY_LENGTH];
    char location[MAX_LOCATION_LENGTH];
    char description[MAX_DESCRIPTION_LENGTH];
    time_t timestamp;
    char prevHash[HASH_LENGTH + 1];
    char hash[HASH_LENGTH + 1];
} JobBlock;

typedef struct BlockNode {
    JobBlock data;
    struct BlockNode* next;
} BlockNode;

typedef struct {
    BlockNode* head;
    int length;
} Blockchain;

// Blockchain operations
Blockchain* createBlockchain();
void addJob(Blockchain* chain, const char* title, const char* company, 
            const char* location, const char* description);
BlockNode* searchJobs(Blockchain* chain, const char* keyword);
bool verifyIntegrity(Blockchain* chain);
void displayJob(JobBlock* job);
void freeBlockchain(Blockchain* chain);

// Hash utilities
void calculateHash(JobBlock* block, char* output);
void bytesToHex(unsigned char* bytes, int len, char* output);

#endif