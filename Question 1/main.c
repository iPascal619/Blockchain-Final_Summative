#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "blockchain.h"

void printMenu() {
    printf("\nBlockchain Job Directory\n");
    printf("1. Add New Job\n");
    printf("2. Search Jobs\n");
    printf("3. Verify Directory Integrity\n");
    printf("4. Exit\n");
    printf("Choose an option: ");
}

int main() {
    Blockchain* jobChain = createBlockchain();
    if (!jobChain) {
        printf("Failed to initialize blockchain\n");
        return 1;
    }

    char choice;
    char buffer[MAX_DESCRIPTION_LENGTH];

    while (1) {
        printMenu();
        scanf(" %c", &choice);
        getchar(); // Clear newline

        switch (choice) {
            case '1': {
                printf("Enter job title: ");
                fgets(buffer, MAX_TITLE_LENGTH, stdin);
                buffer[strcspn(buffer, "\n")] = 0;
                char title[MAX_TITLE_LENGTH];
                strncpy(title, buffer, MAX_TITLE_LENGTH);

                printf("Enter company name: ");
                fgets(buffer, MAX_COMPANY_LENGTH, stdin);
                buffer[strcspn(buffer, "\n")] = 0;
                char company[MAX_COMPANY_LENGTH];
                strncpy(company, buffer, MAX_COMPANY_LENGTH);

                printf("Enter location: ");
                fgets(buffer, MAX_LOCATION_LENGTH, stdin);
                buffer[strcspn(buffer, "\n")] = 0;
                char location[MAX_LOCATION_LENGTH];
                strncpy(location, buffer, MAX_LOCATION_LENGTH);

                printf("Enter job description: ");
                fgets(buffer, MAX_DESCRIPTION_LENGTH, stdin);
                buffer[strcspn(buffer, "\n")] = 0;
                char description[MAX_DESCRIPTION_LENGTH];
                strncpy(description, buffer, MAX_DESCRIPTION_LENGTH);

                addJob(jobChain, title, company, location, description);
                printf("Job added successfully!\n");
                break;
            }
            case '2': {
                printf("Enter search keyword: ");
                fgets(buffer, 100, stdin);
                buffer[strcspn(buffer, "\n")] = 0;

                BlockNode* results = searchJobs(jobChain, buffer);
                if (!results) {
                    printf("No matching jobs found.\n");
                } else {
                    printf("\nSearch Results:\n");
                    BlockNode* current = results;
                    while (current != NULL) {
                        displayJob(&current->data);
                        BlockNode* temp = current;
                        current = current->next;
                        free(temp);
                    }
                }
                break;
            }
            case '3': {
                if (verifyIntegrity(jobChain)) {
                    printf("Directory integrity verified - all blocks are valid.\n");
                } else {
                    printf("WARNING: Directory integrity compromised!\n");
                }
                break;
            }
            case '4': {
                freeBlockchain(jobChain);
                printf("Goodbye!\n");
                return 0;
            }
            default:
                printf("Invalid option. Please try again.\n");
        }
    }

    return 0;
}