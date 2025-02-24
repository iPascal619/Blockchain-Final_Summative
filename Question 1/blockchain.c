#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>  // Include for EVP API
#include "blockchain.h"

void calculateHash(JobBlock* block, char* output) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int len;
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_sha256();

    if (mdctx == NULL) {
        printf("Error creating EVP_MD_CTX.\n");
        return;
    }

    EVP_DigestInit_ex(mdctx, md, NULL);

    // Concatenate all block data
    char buffer[MAX_TITLE_LENGTH + MAX_COMPANY_LENGTH + 
                MAX_LOCATION_LENGTH + MAX_DESCRIPTION_LENGTH + 
                HASH_LENGTH + sizeof(time_t)];

    sprintf(buffer, "%s%s%s%s%ld%s", 
            block->title, 
            block->company,
            block->location,
            block->description,
            block->timestamp,
            block->prevHash);

    EVP_DigestUpdate(mdctx, buffer, strlen(buffer));
    EVP_DigestFinal_ex(mdctx, hash, &len);
    EVP_MD_CTX_free(mdctx);

    bytesToHex(hash, len, output);  // Convert hash to hex
}

void bytesToHex(unsigned char* bytes, int len, char* output) {
    for(int i = 0; i < len; i++) {
        sprintf(output + (i * 2), "%02x", bytes[i]);
    }
    output[len * 2] = '\0';
}

Blockchain* createBlockchain() {
    Blockchain* chain = (Blockchain*)malloc(sizeof(Blockchain));
    if (!chain) return NULL;
    
    chain->head = NULL;
    chain->length = 0;
    return chain;
}

void addJob(Blockchain* chain, const char* title, const char* company, 
            const char* location, const char* description) {
    BlockNode* newNode = (BlockNode*)malloc(sizeof(BlockNode));
    if (!newNode) return;
    
    // Initialize job block
    strncpy(newNode->data.title, title, MAX_TITLE_LENGTH - 1);
    strncpy(newNode->data.company, company, MAX_COMPANY_LENGTH - 1);
    strncpy(newNode->data.location, location, MAX_LOCATION_LENGTH - 1);
    strncpy(newNode->data.description, description, MAX_DESCRIPTION_LENGTH - 1);
    newNode->data.timestamp = time(NULL);
    
    // Set previous hash
    if (chain->head) {
        strncpy(newNode->data.prevHash, chain->head->data.hash, HASH_LENGTH);
    } else {
        memset(newNode->data.prevHash, '0', HASH_LENGTH);
        newNode->data.prevHash[HASH_LENGTH] = '\0';
    }
    
    // Calculate current block hash
    calculateHash(&newNode->data, newNode->data.hash);
    
    // Add to chain
    newNode->next = chain->head;
    chain->head = newNode;
    chain->length++;
}

BlockNode* searchJobs(Blockchain* chain, const char* keyword) {
    BlockNode* results = NULL;
    BlockNode* current = chain->head;
    
    while (current != NULL) {
        if (strstr(current->data.title, keyword) || 
            strstr(current->data.company, keyword) ||
            strstr(current->data.location, keyword) ||
            strstr(current->data.description, keyword)) {
            
            // Create copy of matching block
            BlockNode* match = (BlockNode*)malloc(sizeof(BlockNode));
            if (!match) continue;
            
            memcpy(&match->data, &current->data, sizeof(JobBlock));
            match->next = results;
            results = match;
        }
        current = current->next;
    }
    
    return results;
}

bool verifyIntegrity(Blockchain* chain) {
    if (!chain->head) return true;
    
    BlockNode* current = chain->head;
    while (current->next != NULL) {
        // Verify hash
        char calculatedHash[HASH_LENGTH + 1];
        calculateHash(&current->data, calculatedHash);
        
        if (strcmp(calculatedHash, current->data.hash) != 0) {
            return false;
        }
        
        // Verify link to previous block
        if (strcmp(current->data.prevHash, current->next->data.hash) != 0) {
            return false;
        }
        
        current = current->next;
    }
    
    return true;
}

void displayJob(JobBlock* job) {
    printf("\nJob Title: %s\n", job->title);
    printf("Company: %s\n", job->company);
    printf("Location: %s\n", job->location);
    printf("Description: %s\n", job->description);
    printf("Posted: %s", ctime(&job->timestamp));
    printf("Block Hash: %.16s...\n", job->hash);
}

void freeBlockchain(Blockchain* chain) {
    BlockNode* current = chain->head;
    while (current != NULL) {
        BlockNode* temp = current;
        current = current->next;
        free(temp);
    }
    free(chain);
}
