#include "account.h"
#include "logging.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <time.h>

// Use SHA-256 for password hashing
static void hash_password(const char *password, char *hash_output) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password, strlen(password));
    SHA256_Final(hash, &sha256);
    
    // Convert to hexadecimal string
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hash_output + (i * 2), "%02x", hash[i]);
    }
    hash_output[64] = '\0';
}

/**
 * Create a new account with the specified parameters.
 *
 * This function initializes a new dynamically allocated account structure
 * with the given user ID, hash information derived from the specified plaintext password, email address,
 * and birthdate. Other fields are set to their default values.
 *
 * On success, returns a pointer to the newly created account structure.
 * On error, returns NULL and logs an error message.
 */
account_t *account_create(const char *userid, const char *plaintext_password,
                          const char *email, const char *birthdate) {
    if (!userid || !plaintext_password || !email || !birthdate) {
        return NULL;
    }

    account_t *acc = (account_t *)malloc(sizeof(account_t));
    if (!acc) {
        return NULL;
    }

    //Initialize account
    acc->account_id = rand(); // simple generate
    strncpy(acc->userid, userid, USER_ID_LENGTH - 1);
    acc->userid[USER_ID_LENGTH - 1] = '\0';
    
    // Hashed password
    hash_password(plaintext_password, acc->password_hash);
    
    strncpy(acc->email, email, EMAIL_LENGTH - 1);
    acc->email[EMAIL_LENGTH - 1] = '\0';
    
    strncpy(acc->birthdate, birthdate, BIRTHDATE_LENGTH - 1);
    acc->birthdate[BIRTHDATE_LENGTH - 1] = '\0';

   
    //Set default value
    acc->unban_time = 0;
    acc->expiration_time = 0;
    acc->login_count = 0;
    acc->login_fail_count = 0;
    acc->last_login_time = 0;
    acc->last_ip = 0;

    return acc;
}

void account_free(account_t *acc) {
    if (acc) {
        free(acc);
    }
}

bool account_validate_password(const account_t *acc, const char *plaintext_password) {
    if (!acc || !plaintext_password) {
        return false;
    }

    char hash[HASH_LENGTH];
    hash_password(plaintext_password, hash);
    return strcmp(hash, acc->password_hash) == 0;
}

bool account_update_password(account_t *acc, const char *new_plaintext_password) {
    if (!acc || !new_plaintext_password) {
        return false;
    }

    hash_password(new_plaintext_password, acc->password_hash);
    return true;
}

void account_record_login_success(account_t *acc, ip4_addr_t ip) {
    if (!acc) {
        return;
    }

    acc->login_count++;
    acc->last_login_time = time(NULL);
    acc->last_ip = ip;
    acc->login_fail_count = 0; // Reset the number of failures
}

void account_record_login_failure(account_t *acc) {
    if (!acc) {
        return;
    }

    acc->login_fail_count++;
}

bool account_is_banned(const account_t *acc) {
    if (!acc) {
        return true;
    }

    return acc->unban_time > time(NULL);
}

bool account_is_expired(const account_t *acc) {
    if (!acc) {
        return true;
    }

    return acc->expiration_time != 0 && acc->expiration_time < time(NULL);
}

void account_set_unban_time(account_t *acc, time_t t) {
    if (!acc) {
        return;
    }

    acc->unban_time = t;
}

void account_set_expiration_time(account_t *acc, time_t t) {
    if (!acc) {
        return;
    }

    acc->expiration_time = t;
}

void account_set_email(account_t *acc, const char *new_email) {
    if (!acc || !new_email) {
        return;
    }

    strncpy(acc->email, new_email, EMAIL_LENGTH - 1);
    acc->email[EMAIL_LENGTH - 1] = '\0';
}

bool account_print_summary(const account_t *acct, int fd) {
    if (!acct) {
        return false;
    }

    char buffer[1024];
    int len = snprintf(buffer, sizeof(buffer),
        "Account Summary:\n"
        "User ID: %s\n"
        "Email: %s\n"
        "Birth Date: %s\n"
        "Login Count: %u\n"
        "Failed Login Attempts: %u\n"
        "Last Login: %s"
        "Account Status: %s\n"
        "Account Validity: %s\n",
        acct->userid,
        acct->email,
        acct->birthdate,
        acct->login_count,
        acct->login_fail_count,
        acct->last_login_time ? ctime(&acct->last_login_time) : "Never\n",
        account_is_banned(acct) ? "Banned" : "Active",
        account_is_expired(acct) ? "Expired" : "Valid"
    );

    if (len < 0) {
        return false;
    }

    return write(fd, buffer, len) == len;
}

