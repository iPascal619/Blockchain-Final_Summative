# Blockchain Job Directory - README

## **1. Project Overview**
The Blockchain Job Directory is a decentralized job listing system built using blockchain principles. It ensures data integrity, transparency, and immutability by storing job postings as blocks linked cryptographically using SHA-256 hashing.

## **2. Features**
- Secure job listings stored as immutable blockchain blocks.
- Search functionality to retrieve job postings based on keywords.
- Integrity verification to detect any tampering in the job directory.
- Uses SHA-256 hashing to protect data integrity.

## **3. Compilation and Execution**
### **3.1 Requirements**
- GCC Compiler (Linux/macOS) or MinGW (Windows)
- OpenSSL Library (Ensure it's installed and linked correctly)

### **3.2 Compilation**
Use the following command to compile the project:
```bash
make
```
Or manually compile using:
```bash
gcc -Wall -Wextra -o job_directory main.c blockchain.c -I"/usr/include/openssl" -L"/usr/lib" -lssl -lcrypto
```

### **3.3 Running the Program**
```bash
./job_directory
```

## **4. Blockchain Principles in the Application**
- Each job listing is stored in a block linked to the previous block via a hash.
- The SHA-256 hashing mechanism ensures that any alteration in job listings is detectable.
- The program supports searching for jobs without compromising data security.

## **5. Hashing and Data Integrity**
- SHA-256 is used to generate unique block hashes.
- The `verifyIntegrity()` function checks if any block has been tampered with.
- If a block’s hash does not match the recalculated hash, the system detects an integrity breach.

## **6. Example Output**
- **Adding job listings**:
  - User enters job title, company, location, and description.
  - A new block is created and linked to the blockchain.

- **Searching for jobs**:
  - User enters a keyword.
  - Matching job listings are displayed.

- **Integrity verification**:
  - The system scans all blocks and verifies their hashes.
  - If any modification is detected, the program alerts the user.

## **7. Author**
- **Chukwuma Pascal Onuoha**
- **Project for ALU Blockchain-Based Job Directory**

