#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

// 1. System Design and Architecture - Data Structures

// Student Structure
typedef struct {
    char id[20];
    char name[100];
    char department[50];
    char email[100];
} Student;

// Wallet Structure
typedef struct {
    char address[65];
    char public_key[256];
    char private_key[256];
    double balance;
    Student *owner;
} Wallet;

// Vendor Structure
typedef struct {
    char id[20];
    char name[100];
    char service_type[50]; 
    Wallet *wallet;
} Vendor;

// 4. Token/Cryptocurrency Design
typedef struct {
    char token_name[50];
    unsigned int total_supply;
    unsigned int circulating_supply;
} Token;

// Transaction Structure
typedef struct {
    char id[65];
    char sender_address[65];
    char receiver_address[65];
    double amount;
    char timestamp[30];
    char transaction_type[50]; 
    char signature[256];
    int verified;
} Transaction;

// 5. Block Structure
typedef struct Block {
    unsigned int index;
    char previous_hash[65];
    char timestamp[30];
    unsigned int nonce;
    Transaction transactions[10]; 
    int transaction_count;
    char current_hash[65];
    struct Block *next; 
} Block;

// Blockchain Structure
typedef struct {
    Block *genesis_block;
    Block *latest_block;
    int block_count;
    unsigned int difficulty; 
    Token token;
} Blockchain;

// Global variables
Blockchain *alu_chain;
Wallet **wallets;
int wallet_count = 0;
Vendor **vendors;
int vendor_count = 0;
Transaction *pending_transactions;
int pending_transaction_count = 0;

// 2. Blockchain Cryptography Functions

// Generate SHA-256 hash
void generate_hash(char *input, char *output) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input, strlen(input));
    SHA256_Final(hash, &sha256);
    
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[64] = '\0';
}

// Generate key pair for wallet
void generate_key_pair(char *public_key, char *private_key) {
    RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    
    // Save public key to string
    BIO *public_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(public_bio, rsa);
    
    size_t pub_len = BIO_pending(public_bio);
    BIO_read(public_bio, public_key, pub_len);
    public_key[pub_len] = '\0';
    
    // Save private key to string
    BIO *private_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(private_bio, rsa, NULL, NULL, 0, NULL, NULL);
    
    size_t priv_len = BIO_pending(private_bio);
    BIO_read(private_bio, private_key, priv_len);
    private_key[priv_len] = '\0';
    
    // Clean up
    BIO_free_all(public_bio);
    BIO_free_all(private_bio);
    RSA_free(rsa);
}

// Sign transaction
void sign_transaction(Transaction *transaction, char *private_key) {
    char transaction_data[512];
    sprintf(transaction_data, "%s%s%f%s", 
            transaction->sender_address, 
            transaction->receiver_address, 
            transaction->amount, 
            transaction->timestamp);
    
    RSA *rsa = NULL;
    BIO *bio = BIO_new_mem_buf(private_key, -1);
    PEM_read_bio_RSAPrivateKey(bio, &rsa, NULL, NULL);
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, transaction_data, strlen(transaction_data));
    SHA256_Final(hash, &sha256);
    
    unsigned char signature[256];
    unsigned int signature_len;
    RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, &signature_len, rsa);
    
    // Convert binary signature to hex string
    for(unsigned int i = 0; i < signature_len; i++) {
        sprintf(transaction->signature + (i * 2), "%02x", signature[i]);
    }
    
    // Clean up
    BIO_free_all(bio);
    RSA_free(rsa);
}

// Verify transaction signature
int verify_transaction(Transaction *transaction) {
    char transaction_data[512];
    sprintf(transaction_data, "%s%s%f%s", 
            transaction->sender_address, 
            transaction->receiver_address, 
            transaction->amount, 
            transaction->timestamp);
    
    // Find sender's wallet to get public key
    char *public_key = NULL;
    for(int i = 0; i < wallet_count; i++) {
        if(strcmp(wallets[i]->address, transaction->sender_address) == 0) {
            public_key = wallets[i]->public_key;
            break;
        }
    }
    
    if(public_key == NULL) {
        return 0; // Sender not found
    }
    
    RSA *rsa = NULL;
    BIO *bio = BIO_new_mem_buf(public_key, -1);
    PEM_read_bio_RSAPublicKey(bio, &rsa, NULL, NULL);
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, transaction_data, strlen(transaction_data));
    SHA256_Final(hash, &sha256);
    
    // Convert hex signature back to binary
    unsigned char signature[256];
    for(int i = 0; i < 128; i++) {
        sscanf(transaction->signature + (i * 2), "%02hhx", &signature[i]);
    }
    
    int result = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, 128, rsa);
    
    // Clean up
    BIO_free_all(bio);
    RSA_free(rsa);
    
    return result;
}

// 3. Consensus Mechanism Functions

// Proof of Work implementation
int mine_block(Block *block, unsigned int difficulty) {
    char target[65];
    memset(target, '0', difficulty);
    target[difficulty] = '\0';
    
    char block_header[512];
    char hash_result[65];
    
    block->nonce = 0;
    
    do {
        sprintf(block_header, "%u%s%s%u", 
                block->index, 
                block->previous_hash, 
                block->timestamp, 
                block->nonce);
        
        // Add transactions to header
        for(int i = 0; i < block->transaction_count; i++) {
            char trans_str[256];
            sprintf(trans_str, "%s%s%f", 
                    block->transactions[i].sender_address, 
                    block->transactions[i].receiver_address, 
                    block->transactions[i].amount);
            strcat(block_header, trans_str);
        }
        
        generate_hash(block_header, hash_result);
        
        if(strncmp(hash_result, target, difficulty) == 0) {
            strcpy(block->current_hash, hash_result);
            return 1; // Mining successful
        }
        
        block->nonce++;
    } while(1);
}

// Alternative Proof of Stake implementation
int select_validator(Wallet **validators, int validator_count) {
    double total_stake = 0;
    
    // Calculate total stake
    for(int i = 0; i < validator_count; i++) {
        total_stake += validators[i]->balance;
    }
    
    // Random number between 0 and total_stake
    double random = (double)rand() / RAND_MAX * total_stake;
    
    // Select validator based on stake
    double cumulative = 0;
    for(int i = 0; i < validator_count; i++) {
        cumulative += validators[i]->balance;
        if(random <= cumulative) {
            return i; // Return validator index
        }
    }
    
    return 0; // Default to first validator (shouldn't reach here)
}

// 5. Block & Chain Management Functions

// Create a new block
Block* create_block() {
    Block *new_block = (Block*)malloc(sizeof(Block));
    
    new_block->index = alu_chain->block_count;
    
    // Get previous hash from latest block
    if(alu_chain->latest_block == NULL) {
        // Genesis block
        strcpy(new_block->previous_hash, "0000000000000000000000000000000000000000000000000000000000000000");
    } else {
        strcpy(new_block->previous_hash, alu_chain->latest_block->current_hash);
    }
    
    // Set timestamp
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(new_block->timestamp, sizeof(new_block->timestamp), "%Y-%m-%d %H:%M:%S", t);
    
    // Initialize transaction count
    new_block->transaction_count = 0;
    new_block->next = NULL;
    
    return new_block;
}

// Add transaction to block
int add_transaction(Block *block, Transaction transaction) {
    if(block->transaction_count >= 10) {
        return 0; // Block is full
    }
    
    // Verify transaction
    if(!transaction.verified) {
        if(!verify_transaction(&transaction)) {
            return 0; // Transaction verification failed
        }
        transaction.verified = 1;
    }
    
    // Add transaction to block
    block->transactions[block->transaction_count] = transaction;
    block->transaction_count++;
    
    return 1; // Transaction added successfully
}

// Validate block
int validate_block(Block *block) {
    // Validate hash
    char block_header[512];
    char hash_result[65];
    
    sprintf(block_header, "%u%s%s%u", 
            block->index, 
            block->previous_hash, 
            block->timestamp, 
            block->nonce);
    
    // Add transactions to header
    for(int i = 0; i < block->transaction_count; i++) {
        char trans_str[256];
        sprintf(trans_str, "%s%s%f", 
                block->transactions[i].sender_address, 
                block->transactions[i].receiver_address, 
                block->transactions[i].amount);
        strcat(block_header, trans_str);
    }
    
    generate_hash(block_header, hash_result);
    
    if(strcmp(hash_result, block->current_hash) != 0) {
        return 0; // Hash doesn't match
    }
    
    // Validate transactions
    for(int i = 0; i < block->transaction_count; i++) {
        if(!block->transactions[i].verified) {
            if(!verify_transaction(&block->transactions[i])) {
                return 0; // Transaction verification failed
            }
        }
    }
    
    return 1; // Block is valid
}

// Validate entire blockchain
int validate_chain() {
    Block *current = alu_chain->genesis_block;
    
    while(current != NULL) {
        // Validate current block
        if(!validate_block(current)) {
            return 0; // Block validation failed
        }
        
        // Validate link to next block
        if(current->next != NULL) {
            if(strcmp(current->current_hash, current->next->previous_hash) != 0) {
                return 0; // Chain broken
            }
        }
        
        current = current->next;
    }
    
    return 1; // Chain is valid
}

// Initialize blockchain
void initialize_blockchain() {
    alu_chain = (Blockchain*)malloc(sizeof(Blockchain));
    alu_chain->genesis_block = NULL;
    alu_chain->latest_block = NULL;
    alu_chain->block_count = 0;
    alu_chain->difficulty = 4; 
    
    // Initialize token
    strcpy(alu_chain->token.token_name, "ALUCoin");
    alu_chain->token.total_supply = 10000000; // 10 million tokens
    alu_chain->token.circulating_supply = 0;
    
    // Create genesis block
    Block *genesis = create_block();
    
    // Mine genesis block
    mine_block(genesis, alu_chain->difficulty);
    
    // Add genesis block to chain
    alu_chain->genesis_block = genesis;
    alu_chain->latest_block = genesis;
    alu_chain->block_count = 1;
    
    // Initialize arrays
    wallets = (Wallet**)malloc(sizeof(Wallet*) * 100);
    vendors = (Vendor**)malloc(sizeof(Vendor*) * 20);
    pending_transactions = (Transaction*)malloc(sizeof(Transaction) * 100);
}

// 4. Token Management Functions

// Transfer tokens between wallets
int transfer_tokens(char *sender_address, char *receiver_address, double amount, char *transaction_type, char *private_key) {
    // Find sender wallet
    Wallet *sender_wallet = NULL;
    for(int i = 0; i < wallet_count; i++) {
        if(strcmp(wallets[i]->address, sender_address) == 0) {
            sender_wallet = wallets[i];
            break;
        }
    }
    
    if(sender_wallet == NULL) {
        return 0; // Sender not found
    }
    
    // Check balance
    if(sender_wallet->balance < amount) {
        return 0; // Insufficient balance
    }
    
    // Create transaction
    Transaction new_transaction;
    
    // Generate transaction ID (hash of sender + receiver + amount + time)
    char tx_data[256];
    sprintf(tx_data, "%s%s%.8f%ld", sender_address, receiver_address, amount, time(NULL));
    generate_hash(tx_data, new_transaction.id);
    
    strcpy(new_transaction.sender_address, sender_address);
    strcpy(new_transaction.receiver_address, receiver_address);
    new_transaction.amount = amount;
    
    // Set timestamp
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(new_transaction.timestamp, sizeof(new_transaction.timestamp), "%Y-%m-%d %H:%M:%S", t);
    
    strcpy(new_transaction.transaction_type, transaction_type);
    new_transaction.verified = 0;
    
    // Sign transaction
    sign_transaction(&new_transaction, private_key);
    
    // Add to pending transactions
    pending_transactions[pending_transaction_count] = new_transaction;
    pending_transaction_count++;
    
    return 1; // Transaction created successfully
}

// Process pending transactions
void process_transactions() {
    if(pending_transaction_count == 0) {
        return; // No pending transactions
    }
    
    // Create new block
    Block *new_block = create_block();
    
    // Add transactions to block
    int transactions_added = 0;
    for(int i = 0; i < pending_transaction_count; i++) {
        if(add_transaction(new_block, pending_transactions[i])) {
            transactions_added++;
            
            // Update wallet balances
            for(int j = 0; j < wallet_count; j++) {
                if(strcmp(wallets[j]->address, pending_transactions[i].sender_address) == 0) {
                    wallets[j]->balance -= pending_transactions[i].amount;
                }
                if(strcmp(wallets[j]->address, pending_transactions[i].receiver_address) == 0) {
                    wallets[j]->balance += pending_transactions[i].amount;
                }
            }
            
            // Remove transaction from pending
            if(i < pending_transaction_count - 1) {
                pending_transactions[i] = pending_transactions[pending_transaction_count - 1];
                i--; // Process the swapped transaction next
            }
            pending_transaction_count--;
            
            if(new_block->transaction_count >= 10) {
                break; // Block is full
            }
        }
    }
    
    if(transactions_added > 0) {
        // Mine block
        if(mine_block(new_block, alu_chain->difficulty)) {
            // Add block to chain
            alu_chain->latest_block->next = new_block;
            alu_chain->latest_block = new_block;
            alu_chain->block_count++;
            
            printf("Block #%u added to blockchain with %d transactions\n", 
                   new_block->index, new_block->transaction_count);
        }
    } else {
        free(new_block); // No transactions added, discard block
    }
}

// 7. Command-Line Interface Functions

// Create a new wallet
Wallet* create_wallet(Student *student) {
    Wallet *new_wallet = (Wallet*)malloc(sizeof(Wallet));
    
    // Generate address (hash of student ID + timestamp)
    char address_data[100];
    sprintf(address_data, "%s%ld", student->id, time(NULL));
    generate_hash(address_data, new_wallet->address);
    
    // Generate key pair
    generate_key_pair(new_wallet->public_key, new_wallet->private_key);
    
    new_wallet->balance = 0.0;
    new_wallet->owner = student;
    
    // Add to wallets array
    wallets[wallet_count] = new_wallet;
    wallet_count++;
    
    return new_wallet;
}

// View wallet balance
double view_balance(char *wallet_address) {
    for(int i = 0; i < wallet_count; i++) {
        if(strcmp(wallets[i]->address, wallet_address) == 0) {
            return wallets[i]->balance;
        }
    }
    
    return -1.0; // Wallet not found
}

// Create vendor account
Vendor* create_vendor(char *id, char *name, char *service_type) {
    Vendor *new_vendor = (Vendor*)malloc(sizeof(Vendor));
    strcpy(new_vendor->id, id);
    strcpy(new_vendor->name, name);
    strcpy(new_vendor->service_type, service_type);
    
    // Create wallet for vendor
    Student *vendor_profile = (Student*)malloc(sizeof(Student));
    strcpy(vendor_profile->id, id);
    strcpy(vendor_profile->name, name);
    strcpy(vendor_profile->department, "Vendor");
    sprintf(vendor_profile->email, "%s@alu.vendors.edu", id);
    
    new_vendor->wallet = create_wallet(vendor_profile);
    
    // Add to vendors array
    vendors[vendor_count] = new_vendor;
    vendor_count++;
    
    return new_vendor;
}

// Initialize system with sample data
void initialize_sample_data() {
    // Create sample students
    Student *student1 = (Student*)malloc(sizeof(Student));
    strcpy(student1->id, "S12345");
    strcpy(student1->name, "Chukwuma Onuoha");
    strcpy(student1->department, "Software Engineering");
    strcpy(student1->email, "c.onuoha@alustudent.com");
    
    Student *student2 = (Student*)malloc(sizeof(Student));
    strcpy(student2->id, "S67890");
    strcpy(student2->name, "Jane Smith");
    strcpy(student2->department, "Business");
    strcpy(student2->email, "jane.smith@alustudent.com");
    
    // Create student wallets
    Wallet *wallet1 = create_wallet(student1);
    Wallet *wallet2 = create_wallet(student2);
    
    // Add initial balance (from university)
    wallet1->balance = 1000.0;
    wallet2->balance = 1500.0;
    
    // Create vendors
    create_vendor("V001", "ALU Food court", "Food Services");
    create_vendor("V002", "University Library", "Academic Services");
    create_vendor("V003", "Tuition Office", "Financial Services");
    
    printf("Sample data initialized with %d students and %d vendors\n", wallet_count, vendor_count);
}

// 8. Security and Testing Functions

// Backup blockchain to file
void backup_blockchain(const char *filename) {
    FILE *file = fopen(filename, "w");
    if(file == NULL) {
        printf("Error opening backup file\n");
        return;
    }
    
    // Write blockchain metadata
    fprintf(file, "ALUChain Backup\n");
    fprintf(file, "BlockCount: %d\n", alu_chain->block_count);
    fprintf(file, "Difficulty: %u\n", alu_chain->difficulty);
    fprintf(file, "Token: %s\n", alu_chain->token.token_name);
    fprintf(file, "TotalSupply: %u\n", alu_chain->token.total_supply);
    fprintf(file, "CirculatingSupply: %u\n\n", alu_chain->token.circulating_supply);
    
    // Write blocks
    Block *current = alu_chain->genesis_block;
    while(current != NULL) {
        fprintf(file, "Block #%u\n", current->index);
        fprintf(file, "PreviousHash: %s\n", current->previous_hash);
        fprintf(file, "Timestamp: %s\n", current->timestamp);
        fprintf(file, "Nonce: %u\n", current->nonce);
        fprintf(file, "Hash: %s\n", current->current_hash);
        fprintf(file, "Transactions: %d\n", current->transaction_count);
        
        // Write transactions
        for(int i = 0; i < current->transaction_count; i++) {
            fprintf(file, "  Tx %d: %s -> %s = %.2f ALUCoin (%s)\n", 
                   i + 1,
                   current->transactions[i].sender_address,
                   current->transactions[i].receiver_address,
                   current->transactions[i].amount,
                   current->transactions[i].transaction_type);
        }
        
        fprintf(file, "\n");
        current = current->next;
    }
    
    fclose(file);
    printf("Blockchain backed up to %s\n", filename);
}

// Main menu
void display_menu() {
    printf("\n=== ALU Blockchain Payment System ===\n");
    printf("1. Create Student Wallet\n");
    printf("2. View Wallet Balance\n");
    printf("3. Make Payment\n");
    printf("4. Process Pending Transactions\n");
    printf("5. Display Blockchain\n");
    printf("6. Validate Blockchain\n");
    printf("7. Backup Blockchain\n");
    printf("8. Exit\n");
    printf("Enter your choice: ");
}

// Helper functions for menu
void display_blockchain() {
    printf("\n=== ALU Blockchain ===\n");
    printf("Total Blocks: %d\n", alu_chain->block_count);
    printf("Difficulty: %u\n", alu_chain->difficulty);
    printf("Token: %s (Supply: %u)\n\n", 
           alu_chain->token.token_name, 
           alu_chain->token.total_supply);
    
    Block *current = alu_chain->genesis_block;
    int block_num = 1;
    
    while(current != NULL) {
        printf("Block #%d (Index: %u)\n", block_num, current->index);
        printf("Timestamp: %s\n", current->timestamp);
        printf("Hash: %s\n", current->current_hash);
        printf("Transactions: %d\n", current->transaction_count);
        
        for(int i = 0; i < current->transaction_count; i++) {
            printf("  [%d] %s -> %s: %.2f ALUCoin (%s)\n", 
                   i + 1,
                   current->transactions[i].sender_address,
                   current->transactions[i].receiver_address,
                   current->transactions[i].amount,
                   current->transactions[i].transaction_type);
        }
        
        printf("\n");
        current = current->next;
        block_num++;
    }
}

// Main function
int main() {
    // Initialize libraries
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    // Seed random number generator
    srand(time(NULL));
    
    // Initialize blockchain
    initialize_blockchain();
    
    // Load sample data
    initialize_sample_data();
    
    int choice;
    char input[256];
    
    do {
        display_menu();
        scanf("%d", &choice);
        getchar(); // Clear newline
        
        switch(choice) {
            case 1: // Create wallet
                {
                    Student *new_student = (Student*)malloc(sizeof(Student));
                    
                    printf("Enter Student ID: ");
                    fgets(new_student->id, sizeof(new_student->id), stdin);
                    new_student->id[strcspn(new_student->id, "\n")] = 0;
                    
                    printf("Enter Student Name: ");
                    fgets(new_student->name, sizeof(new_student->name), stdin);
                    new_student->name[strcspn(new_student->name, "\n")] = 0;
                    
                    printf("Enter Department: ");
                    fgets(new_student->department, sizeof(new_student->department), stdin);
                    new_student->department[strcspn(new_student->department, "\n")] = 0;
                    
                    printf("Enter Email: ");
                    fgets(new_student->email, sizeof(new_student->email), stdin);
                    new_student->email[strcspn(new_student->email, "\n")] = 0;
                    
                    Wallet *new_wallet = create_wallet(new_student);
                    printf("\nWallet created successfully!\n");
                    printf("Address: %s\n", new_wallet->address);
                    printf("Initial Balance: %.2f ALUCoin\n", new_wallet->balance);
                }
                break;
                
            case 2: // View balance
                {
                    printf("Enter Wallet Address: ");
                    fgets(input, sizeof(input), stdin);
                    input[strcspn(input, "\n")] = 0;
                    
                    double balance = view_balance(input);
                    if(balance >= 0) {
                        printf("\nWallet Balance: %.2f ALUCoin\n", balance);
                    } else {
                        printf("\nWallet not found\n");
                    }
                }
                break;
                
            case 3: // Make payment
                {
                    char sender_address[65];
                    char receiver_address[65];
                    double amount;
                    char type[50];
                    char private_key[256];
                    
                    printf("Enter Your Wallet Address: ");
                    fgets(sender_address, sizeof(sender_address), stdin);
                    sender_address[strcspn(sender_address, "\n")] = 0;
                    
                    // Find wallet to get private key
                    Wallet *sender_wallet = NULL;
                    for(int i = 0; i < wallet_count; i++) {
                        if(strcmp(wallets[i]->address, sender_address) == 0) {
                            sender_wallet = wallets[i];
                            break;
                        }
                    }
                    
                    if(sender_wallet == NULL) {
                        printf("\nWallet not found\n");
                        break;
                    }
                    
                    // Display available vendors
                    printf("\nAvailable Payment Recipients:\n");
                    for(int i = 0; i < vendor_count; i++) {
                        printf("%d. %s (%s) - Address: %s\n", 
                               i + 1, 
                               vendors[i]->name, 
                               vendors[i]->service_type,
                               vendors[i]->wallet->address);
                    }
                    
                    printf("\nEnter Recipient Wallet Address: ");
                    fgets(receiver_address, sizeof(receiver_address), stdin);
                    receiver_address[strcspn(receiver_address, "\n")] = 0;
                    
                    printf("Enter Amount: ");
                    scanf("%lf", &amount);
                    getchar(); // Clear newline
                    
                    printf("Enter Payment Type (e.g., 'Tuition Fee', 'Cafeteria Payment'): ");
                    fgets(type, sizeof(type), stdin);
                    type[strcspn(type, "\n")] = 0;
                    
                    // Use stored private key 
                    strcpy(private_key, sender_wallet->private_key);
                    
                    if(transfer_tokens(sender_address, receiver_address, amount, type, private_key)) {
                        printf("\nPayment initiated successfully!\n");
                        printf("Transaction added to pending queue.\n");
                    } else {
                        printf("\nPayment failed. Check balance and addresses.\n");
                    }
                }
                break;
                
            case 4: // Process transactions
                printf("\nProcessing pending transactions...\n");
                process_transactions();
                printf("Done. %d transactions remaining in queue.\n", pending_transaction_count);
                break;
                
            case 5: // Display blockchain
                display_blockchain();
                break;
                
            case 6: // Validate blockchain
                if(validate_chain()) {
                    printf("\nBlockchain validation successful. Chain is valid.\n");
                } else {
                    printf("\nBlockchain validation failed! Chain is compromised.\n");
                }
                break;
                
            case 7: // Backup blockchain
                backup_blockchain("alu_blockchain_backup.txt");

                break;
                
            case 8: // Exit
                printf("\nExiting ALU Blockchain Payment System. Goodbye!\n");
                break;
                
            default:
                printf("\nInvalid choice. Please try again.\n");
                
        }
    } while(choice != 8);
    
    // Cleanup resources before exit
    // Free memory for blocks
    Block *current = alu_chain->genesis_block;
    Block *next;
    while(current != NULL) {
        next = current->next;
        free(current);
        current = next;
    }
    
    // Free memory for wallets and students
    for(int i = 0; i < wallet_count; i++) {
        free(wallets[i]->owner);
        free(wallets[i]);
    }
    free(wallets);
    
    // Free memory for vendors
    for(int i = 0; i < vendor_count; i++) {
        free(vendors[i]);
    }
    free(vendors);
    
    // Free memory for pending transactions
    free(pending_transactions);
    
    // Free memory for blockchain
    free(alu_chain);
    
    // Cleanup OpenSSL
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    
    return 0;
}

// Unit tests for core functions
#ifdef TESTING
#include <assert.h>

void run_tests() {
    printf("Running unit tests...\n");
    
    // Test hash generation
    char hash_result[65];
    generate_hash("test", hash_result);
    assert(strlen(hash_result) == 64);
    
    // Test wallet creation
    Student test_student = {"T001", "Test Student", "Testing", "test@alu.edu"};
    Wallet *test_wallet = create_wallet(&test_student);
    assert(test_wallet != NULL);
    assert(strlen(test_wallet->address) == 64);
    assert(strlen(test_wallet->public_key) > 0);
    assert(strlen(test_wallet->private_key) > 0);
    
    // Test transaction creation and verification
    test_wallet->balance = 100.0;
    
    Student test_student2 = {"T002", "Test Student 2", "Testing", "test2@alu.edu"};
    Wallet *test_wallet2 = create_wallet(&test_student2);
    
    int tx_result = transfer_tokens(
        test_wallet->address,
        test_wallet2->address,
        50.0,
        "Test Payment",
        test_wallet->private_key
    );
    assert(tx_result == 1);
    assert(pending_transaction_count > 0);
    
    // Test transaction verification
    assert(verify_transaction(&pending_transactions[pending_transaction_count - 1]) == 1);
    
    // Test block creation
    Block *test_block = create_block();
    assert(test_block != NULL);
    assert(test_block->index == alu_chain->block_count);
    
    // Test adding transaction to block
    int add_result = add_transaction(test_block, pending_transactions[pending_transaction_count - 1]);
    assert(add_result == 1);
    assert(test_block->transaction_count == 1);
    
    // Test mining
    int mine_result = mine_block(test_block, 2); // Low difficulty for testing
    assert(mine_result == 1);
    assert(strncmp(test_block->current_hash, "00", 2) == 0);
    
    // Test block validation
    assert(validate_block(test_block) == 1);
    
    // Test blockchain validation
    Block *old_latest = alu_chain->latest_block;
    alu_chain->latest_block->next = test_block;
    alu_chain->latest_block = test_block;
    alu_chain->block_count++;
    
    assert(validate_chain() == 1);
    
    // Cleanup test data
    alu_chain->latest_block = old_latest;
    alu_chain->latest_block->next = NULL;
    alu_chain->block_count--;
    free(test_block);
    
    printf("All tests passed!\n");
}

int main_test() {
    // Initialize for testing
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    srand(time(NULL));
    initialize_blockchain();
    
    // Run tests
    run_tests();
    
    // Cleanup
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    
    return 0;
}
#endif

                
