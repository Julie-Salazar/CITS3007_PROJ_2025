#include "account.h"
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include "logging.h"
#include <fcntl.h>
#include <argon2.h>
#include <sys/random.h>


// Define default Argon2id parameters
#ifndef ARGON2_T_COST
#define ARGON2_T_COST 5
#endif

#ifndef ARGON2_M_COST
#define ARGON2_M_COST 7168
#endif

#ifndef ARGON2_PARALLELISM
#define ARGON2_PARALLELISM 1
#endif

#define SALT_LENGTH 16

// Forward declaration of secure_zero_memory
static void secure_zero_memory(void *ptr, size_t len);


/**
*@brief Creates a new account.
*
*This fuction creates a new account with the provided user ID, password, email, and birthdate.
*
*@param userid The user ID.
*@param plaintext_password The password in plaintext.
*@param email The email address.
*@param birthdate The birthdate in the format "YYYY-MM-DD".
*/
account_t *account_create(const char *userid, const char *plaintext_password,
                          const char *email, const char *birthdate)
{
  // Validate input parameters
  if (userid == NULL || plaintext_password == NULL || email == NULL || birthdate == NULL) {
    log_message(LOG_ERROR, "account_create: NULL argument");
    return NULL;
  }

  // Validate user ID length
  size_t userid_len = 0;
  for (userid_len = 0; 
       userid_len < USER_ID_LENGTH && userid[userid_len] != '\0'; 
       userid_len++);
  
  if (userid_len == 0 || userid_len >= USER_ID_LENGTH) {
    log_message(LOG_ERROR, "account_create: Invalid user ID length");
    return NULL;
  }

  // Check for leading and trailing spaces
  if (userid[0] == ' ') {
    log_message(LOG_ERROR, "account_create: User ID cannot start with a space");
    return NULL;
  }

  if (userid[userid_len - 1] == ' ') {
    log_message(LOG_ERROR, "account_create: User ID cannot end with a space");
    return NULL;
  }

  // Check for spaces in the user ID
  for (size_t i = 0; i < userid_len; i++) {
    if (userid[i] == ' ') {
      log_message(LOG_ERROR, "account_create: User ID cannot contain spaces");
      return NULL;
    }
  }

  // Validate email length
  size_t email_len = 0;
  for (email_len = 0; 
       email_len < EMAIL_LENGTH && email[email_len] != '\0'; 
       email_len++);
  
  if (email_len == 0 || email_len >= EMAIL_LENGTH) {
    log_message(LOG_ERROR, "account_create: Invalid email length");
    return NULL;
  }

  // Validate birthdate format (YYYY-MM-DD)
  size_t birthdate_len = strlen(birthdate);
  if (birthdate_len != 10 || 
      birthdate[4] != '-' || 
      birthdate[7] != '-') {
    log_message(LOG_ERROR, "account_create: Invalid birthdate format, must be YYYY-MM-DD");
    return NULL;
  }
  
  // Check that birthdate contains only digits and hyphens
  for (size_t i = 0; i < birthdate_len; i++) {
    if (i == 4 || i == 7) {
      if (birthdate[i] != '-') {
        log_message(LOG_ERROR, "account_create: Invalid birthdate format, expected hyphens at positions 4 and 7");
        return NULL;
      }
    } else if (!isdigit((unsigned char)birthdate[i])) {
      log_message(LOG_ERROR, "account_create: Birthdate contains non-digit characters");
      return NULL;
    }
  }

  // Parse and validate date components
  int year = 0, month = 0, day = 0;
  
  // Safe parsing of integers with range checking
  if (sscanf(birthdate, "%4d-%2d-%2d", &year, &month, &day) != 3) {
    log_message(LOG_ERROR, "account_create: Failed to parse birthdate components");
    return NULL;
  }
  
  if (year < 1900 || year > 2100) {
    log_message(LOG_ERROR, "account_create: Invalid year in birthdate (%d)", year);
    return NULL;
  }
  
  if (month < 1 || month > 12) {
    log_message(LOG_ERROR, "account_create: Invalid month in birthdate (%d)", month);
    return NULL;
  }
  
  // Determine maximum days in month
  int max_day = 31;
  if (month == 4 || month == 6 || month == 9 || month == 11) {
    max_day = 30;
  } else if (month == 2) {
    // Check for leap year
    if ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)) {
      max_day = 29;
    } else {
      max_day = 28;
    }
  }
  
  if (day < 1 || day > max_day) {
    log_message(LOG_ERROR, "account_create: Invalid day in birthdate (%d)", day);
    return NULL;
  }
  
  // Allocate account struct with calloc (initializes memory to zero)
  account_t *account = (account_t *)calloc(1, sizeof(account_t));
  if (account == NULL) {
    log_message(LOG_ERROR, "account_create: Failed to allocate memory for account");
    return NULL;
  }

  // Copy userid (ensuring null termination)
  strncpy(account->userid, userid, USER_ID_LENGTH - 1);
  account->userid[USER_ID_LENGTH - 1] = '\0';

  // Hash the password securely using argon2id
  char hashed_pw[HASH_LENGTH];
  uint8_t salt[SALT_LENGTH];

  for (size_t i = 0; i < SALT_LENGTH; i++) {
    salt[i] = (unsigned char)(rand() % 256);
  }

  int result = argon2id_hash_encoded(
  ARGON2_T_COST,
  ARGON2_M_COST,
  ARGON2_PARALLELISM,
  plaintext_password, strlen(plaintext_password),
  salt, SALT_LENGTH,
  32,
  hashed_pw, HASH_LENGTH
  );

  if (result != ARGON2_OK) {
    log_message(LOG_ERROR, "account_create: Argon2id hashing failed");
    secure_zero_memory(account, sizeof(account_t));
    free(account);
  return NULL;
  }

  strncpy(account->password_hash, hashed_pw, HASH_LENGTH - 1);
  account->password_hash[HASH_LENGTH - 1] = '\0';

  strncpy(account->email, email, EMAIL_LENGTH - 1);
  account->email[EMAIL_LENGTH - 1] = '\0';

  strncpy(account->birthdate, birthdate, BIRTHDATE_LENGTH - 1);
  account->birthdate[BIRTHDATE_LENGTH - 1] = '\0';

  unsigned int rand_val = (unsigned int)rand();
  time_t current_time = time(NULL); 

  if (current_time == (time_t)-1) {
    secure_zero_memory(account, sizeof(account_t));
    free(account);
  return NULL;
  }
  account->account_id = (int64_t)current_time ^ ((int64_t)rand_val << 32 | (int64_t)rand_val);
  account->unban_time = 0;
  account->expiration_time = 0;
  account->login_count = 0;
  account->login_fail_count = 0;
  account->last_login_time = 0;
  account->last_ip = 0;
  
  // For now, zero out the password hash area
  memset(account->password_hash, 0, HASH_LENGTH);

  // Copy email (ensuring null termination)
  strncpy(account->email, email, EMAIL_LENGTH - 1);
  account->email[EMAIL_LENGTH - 1] = '\0';
 
  // Copy birthdate (ensuring null termination)
  strncpy(account->birthdate, birthdate, BIRTHDATE_LENGTH - 1);
  account->birthdate[BIRTHDATE_LENGTH - 1] = '\0';

  // Set unique account ID using a more secure method
  // Combine current time with a random number to reduce collision chance

  
  if (current_time == (time_t)(-1)) {
    log_message(LOG_ERROR, "account_create: Failed to get current time");
    secure_zero_memory(account, sizeof(account_t));
    free(account);
    return NULL;
  }
  
  // Use XOR to combine the values, reducing chance of collisions
  account->account_id = (int64_t)current_time ^ ((int64_t)rand_val << 32 | (int64_t)rand_val);

  // Set default values
  account->unban_time = 0;        // Not banned
  account->expiration_time = 0;    // No expiration
  account->login_count = 0;        // No successful logins
  account->login_fail_count = 0;   // No failed logins
  account->last_login_time = 0;    // Never logged in
  account->last_ip = 0;            // No last IP
  
  log_message(LOG_INFO, "account_create: Successfully created account for user %s", account->userid);
  return account;
}

// Secure memory clearing function that won't be optimized away by the compiler
static void secure_zero_memory(void *ptr, size_t len) {
  volatile unsigned char *p = (volatile unsigned char *)ptr;
  while (len--) {
    *p++ = 0;
  }
}

void account_free(account_t *acc) {
  if (acc == NULL) {
    log_message(LOG_WARN, "account_free: Called with NULL account pointer");
    return;
  }
  
  log_message(LOG_DEBUG, "account_free: Freeing account for user %s", acc->userid);
  
  // Clear sensitive data before freeing
  secure_zero_memory(acc->password_hash, HASH_LENGTH);
  
  // Clear entire structure
  secure_zero_memory(acc, sizeof(account_t));
  
  // Free the memory
  free(acc);
  
  log_message(LOG_DEBUG, "account_free: Account memory cleared and freed");
}





/**
 * \brief           Validates the provided password against the stored hashed password in the account.
 * \param[in]       acc: Pointer to the account containing the hashed password.
 * \param[in]       plaintext_password: The password to validate.
 * \return          True if the password matches the stored hash, false otherwise.
 *
 * \note            Preconditions: both params are non-NULL and plaintext_password is a valid, NULL-terminated string.
 */
bool account_validate_password(const account_t *acc, const char *plaintext_password) {
  if(argon2id_verify(acc->password_hash, plaintext_password, strlen(plaintext_password)) == ARGON2_OK) {
    log_message(LOG_INFO, "Password verified for account %d.", acc->account_id);
    return true;
  }
  else {
    log_message(LOG_INFO, "Password verification failed for account %d.", acc->account_id);
    return false;
  }
}

/**
 * \brief           Generates a unique salt to be used in the password hashing process
 * \param[in]       salt: Pointer to byte buffer to store the generated salt
 * \param[in]       length: Length of the salt buffer in bytes
 * \return          0 on successful salt generation, -1 otherwise.
 * 
 * \note            Preconditions: salt is non-NULL and length > 0.
 */
int generate_salt(uint8_t *salt, size_t length) {
  // Set flags to 0 as none are needed.
  ssize_t result = getrandom(salt, length, 0);

  // Check for failure of getrandom()
  if(result < 0 || (size_t)result != length) {
    log_message(LOG_WARN, "getrandom() failed. Return value: %d", result);
    return -1;
  }
  return 0;
}

/**
 * \brief           Updates the password of the given account.
 * \param[in]       acc: Pointer to the account whose password will be updated.
 * \param[in]       new_plaintext_password: The new password to be set.
 * \return          True if the password was successfully updated, false otherwise.
 * 
 * \note            Preconditions: both params are non-NULL and new_plaintext_password is a valid, NULL-terminated string.
 */
bool account_update_password(account_t *acc, const char *new_plaintext_password) {  

  char hashed_pw[HASH_LENGTH];
  uint8_t salt[SALT_LENGTH];
  
  // Check for successful salt generation
  if(generate_salt(salt, SALT_LENGTH) != 0) {
    return false;
  }

  // Argon2id parameters 
  uint32_t t_cost = ARGON2_T_COST; // Time cost
  uint32_t m_cost = ARGON2_M_COST; // Memory cost
  uint32_t parallelism = ARGON2_PARALLELISM;

  int result = argon2id_hash_encoded( 
    t_cost, m_cost, parallelism,
    new_plaintext_password, strlen(new_plaintext_password),
    salt, SALT_LENGTH,
    32,
    hashed_pw, HASH_LENGTH
  );

  if(result != ARGON2_OK) {
    log_message(LOG_WARN, "Argon2id hashing failed. Output: %d", result);
    return false;
  }

  // Copy password hash to account struct, ensuring NULL termination.
  strncpy(acc->password_hash, hashed_pw, HASH_LENGTH - 1);
  acc->password_hash[HASH_LENGTH - 1] = '\0';

  return true;
}



void account_record_login_success(account_t *acc, ip4_addr_t ip) {

  if (acc != NULL) { 
    acc->login_fail_count = 0; // reset login fail count
    acc->login_count++;
    acc->last_login_time = time(NULL);
    acc->last_ip = ip;  
  }
}

void account_record_login_failure(account_t *acc) {
  if (acc != NULL) {
    acc->login_count = 0; // reset login count
    acc->login_fail_count++;
  }

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

/**
*@brief Checks if the account is currently banned.
*
*An account is considered banned if the current system time is earlier than the `unban_time`.
*
*@param acc A pointer to the account structure to check.
*@return true if the account is banned, false otherwise.
*/
bool account_is_banned(const account_t *acc) {
  
  if (!acc) return false;
  time_t now = time(NULL);
  return acc->unban_time > now;
}

/**
*@brief Checks if the account has expired.
*
*An account is considered expired if the current system time is equal to or later than the expiration_time.
*If the expiration time is 0, the account is treated as not expired.
*
*@param acc A pointer to the account structure to check.
*@return true if the account has expired, false otherwise.
*/
bool account_is_expired(const account_t *acc) {
  
  if (!acc) return false;
  time_t now = time(NULL);
  return acc->expiration_time > 0 && acc->expiration_time <= now;
}
/**
*@brief Sets the unban time for an account.
*
*This function updates the `unban_time` field of the account. If the current time is before the unban time,
*the account will be considered banned.
*
*@param acc A pointer to the account structure to modify.
*@param t The UNIX timestamp (time_t) representing when the ban ends.
*/
void account_set_unban_time(account_t *acc, time_t t) {
  
  if (!acc) return;
  acc->unban_time = t;
}
/**
*@brief Sets the expiration time for an account.
*
*This function updates the `expiration_time` field. If the current time is later than or equal to this time,
*the account is considered expired.
*
*@param acc A pointer to the account structure to modify.
*@param t The UNIX timestamp (time_t) representing when the account should expire.
*/
void account_set_expiration_time(account_t *acc, time_t t) {

  if (!acc) return;
  acc->expiration_time = t;
}

void account_set_email(account_t *acc, const char *new_email) {
    if (!acc || !new_email) {
        log_message(LOG_ERROR, "account_set_email: NULL argument");
        return;
    }

    
    // Verify email length
    size_t email_len = strlen(new_email);
    if (email_len == 0 || email_len >= EMAIL_LENGTH) {
        log_message(LOG_ERROR, "account_set_email: Invalid email length");
        return;
    }

    
    // Verify email format
    bool has_at = false;
    bool has_dot = false;
    bool has_domain = false;
    int at_pos = -1;

    for (size_t i = 0; i < email_len; i++) {
        // Check for illegal characters
        if (!isprint((unsigned char)new_email[i])) {
            log_message(LOG_ERROR, "account_set_email: Email contains non-printable characters");
            return;
        }

        if (new_email[i] == '@') {
            if (has_at || i == 0 || i == email_len - 1) {
                log_message(LOG_ERROR, "account_set_email: Invalid @ symbol position");
                return;
            }
            has_at = true;
            at_pos = i;
        }
        else if (new_email[i] == '.') {
            if (i == 0 || i == email_len - 1 || i == (size_t)at_pos + 1) {
                log_message(LOG_ERROR, "account_set_email: Invalid . symbol position");
                return;
            }
            has_dot = true;
            if (at_pos != -1 && i > (size_t)at_pos) {
                has_domain = true;
            }
        }
    }

    if (!has_at || !has_dot || !has_domain) {
        log_message(LOG_ERROR, "account_set_email: Invalid email format");
        return;
    }

    // Safely copy the mailbox
    strncpy(acc->email, new_email, EMAIL_LENGTH - 1);
    acc->email[EMAIL_LENGTH - 1] = '\0';

    log_message(LOG_INFO, "account_set_email: Successfully updated email for user %s", acc->userid);
}

bool account_print_summary(const account_t *acct, int fd) {

  // check if account is non-NULL
  if (!acct) {
    return false;
  }
  // check if file descriptor is valid and open for writing 
  if (fcntl(fd, F_GETFD) == -1) {
    return false;
}
  // print account summary to the file descriptor
  dprintf(fd, "User ID: %s\n", acct->userid);
  dprintf(fd, "Email: %s\n", acct->email);
  dprintf(fd, "Number of successful login attempts: %u\n", acct->login_count);
  dprintf(fd, "Number of unsuccessful login attempts: %u\n", acct->login_fail_count);
  dprintf(fd, "Time of last successful login: %ld\n", acct->last_login_time);
  dprintf(fd, "Last IP connected from: %u\n", acct->last_ip);
  return true;

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

