#include "account.h"
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <inttypes.h>
#include <stdio.h>
#include "logging.h"
#include <argon2.h>
#include <sys/random.h>
#include "banned.h"

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

// #define BCRYPT_WORK_FACTOR 12


account_t *account_create(const char *userid, const char *plaintext_password,
                          const char *email, const char *birthdate
                      )
{
  if (userid == NULL || plaintext_password == NULL || email == NULL || birthdate == NULL) { // check for NULL arguments
    log_message(LOG_ERROR, "account_create: NULL argument");
    return NULL;
  }

size_t userid_len = 0;
for (userid_len = 0; 
     userid_len < USER_ID_LENGTH && userid[userid_len] != '\0'; 
     userid_len++)
     ; // find the length of the user ID
  if (userid_len == 0 || userid_len >= USER_ID_LENGTH) { // check for empty or too long user ID
    log_message(LOG_ERROR, "account_create: Invalid user ID length");
    return NULL;
  }

  if (userid[0] == ' ') { // check for leading spaces
    log_message(LOG_ERROR, "account_create: User ID cannot start with a space");
    return NULL;
  }

  if (userid[userid_len - 1] == ' ') { // check for trailing spaces
    log_message(LOG_ERROR, "account_create: User ID cannot end with a space");
    return NULL;
  }

if (userid[userid_len] == ' ') {//check for inbetween spaces
  log_message(LOG_ERROR, "account_create: User ID contains spaces");
    return NULL;
  }

  //email validation checking that it contains an '@' and a '.' and that the '@' comes before the '.'
  size_t email_len = 0;
  for (email_len = 0; email_len < EMAIL_LENGTH && email[email_len] != '\0'; email_len++); // find the length of the email
  
  if (email_len == 0 || email_len >= EMAIL_LENGTH) { // check for empty or too long email
    log_message(LOG_ERROR, "account_create: Invalid email length");
    return NULL;
  }

  //making sure that it has arroba before the dot 
  // int arroba = 0;
  // for(size_t i = 0; i < email_len; i++) {
  //   unsigned char c = (unsigned char) email[i];
  //   if (c == '.' && arroba == 0 || isspace(c)) { // check for '.' before '@'
  //     log_message("account_create: Invalid email format");
  //     return NULL;
  //   }
  //   if (email[i] == '@') {
  //     arroba++;
  //   }
  // }
  // if (!arroba) { // check for '@' in the email
  //   log_message("account_create: missing '@' in email");
  //   return NULL;
  // }

  //valaidation of birthdate in format YYYY-MM-DD

  if (strlen(birthdate) != 10 || 
  birthdate[4] != '-' || 
  birthdate[7] != '-') {
    log_message(LOG_ERROR, "Error: Invalid birthdate format, must be YYYY-MM-DD");
  return NULL;
}
  
//check if the birthdate digits are valid 

for (int i = 0; i < 10; i++) {
  if (i == 4 || i == 7) continue; // skip the '-' characters
  if (!isdigit((unsigned char)birthdate[i])) {
    log_message(LOG_ERROR, "Error: Birthdate contains non-digit characters");
    return NULL;
  }
}

  //validation of date value ranges

  int year = (birthdate[0] - '0') * 1000 + (birthdate[1] - '0') * 100 + (birthdate[2] - '0') * 10 + (birthdate[3] - '0');
  int month = (birthdate[5] - '0') * 10 + (birthdate[6] - '0');
  int day = (birthdate[8] - '0') * 10 + (birthdate[9] - '0');
  if (month < 1 || month > 12) {
    log_message(LOG_ERROR, "Error: Invalid month in birthdate");
    return NULL;
  }
   int max_day = 31;
   if (month == 4 || month == 6 || month == 9 || month == 11) {
    max_day = 30;
  } else if (month == 2) {
    if ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)) {
      max_day = 29; // leap year
    } else {
      max_day = 28; // non-leap year
    }
  }
  if (day < 1 || day > max_day) {
    log_message(LOG_ERROR, "Error: Invalid day in birthdate");
    return NULL;
  }
  account_t *account = (account_t *)calloc(1, sizeof(account_t));
  if (account == NULL) {
    log_message(LOG_ERROR, "Error: Failed to allocate memory for account");
      return NULL;
  }

  // Copy userid (ensuring null termination)
  strncpy(account->userid, userid, USER_ID_LENGTH - 1);
  account->userid[USER_ID_LENGTH - 1] = '\0';

   // Generate bcrypt hash of the password
  // char salt[BCRYPT_SALT_LEN];
   // Generate a random salt
  // if (bcrypt_gensalt(BCRYPT_WORK_FACTOR, salt) != 0) {
  //   log_message(LOG_ERROR, "Error: Failed to generate bcrypt salt");
  //   free(account);
  //   return NULL;
  // }
  
   // Hash the password using the generated salt
  // if (bcrypt_hashpw(plaintext_password, salt, account->password_hash) != 0) {
  //   log_message(LOG_ERROR, "Error: Failed to hash password");
  //   free(account);
  //   return NULL;
  // }
  log_message(LOG_DEBUG, "account_create: Successfully hashed password for user %s", userid);

  // Copy email (ensuring null termination)
  strncpy(account->email, email, EMAIL_LENGTH - 1);
  account->email[EMAIL_LENGTH - 1] = '\0';
 
  // Copy birthdate (ensuring null termination)
  strncpy(account->birthdate, birthdate, BIRTHDATE_LENGTH - 1);
  account->birthdate[BIRTHDATE_LENGTH - 1] = '\0';

  // Set default values
  account->account_id = (int64_t)time(NULL) ^ (int64_t)rand(); // Simple unique ID generation
  account->unban_time = 0;        // Not banned
  account->expiration_time = 0;    // No expiration
  account->login_count = 0;        // No successful logins
  account->login_fail_count = 0;   // No failed logins
  account->last_login_time = 0;    // Never logged in
  account->last_ip = 0;            // No last IP
  
  log_message(LOG_INFO, "account_create: Successfully created account for user %s with ID %" PRId64, 
    account->userid, account->account_id);

  return account;
}





void account_free(account_t *acc) {
   if (acc != NULL) {
       // Clear sensitive data before freeing
       memset(acc->password_hash, 0, HASH_LENGTH);
       
       // Free the memory
       free(acc);
   }
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
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) ip;
}

void account_record_login_failure(account_t *acc) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
}

bool account_is_banned(const account_t *acc) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  return false;
}

bool account_is_expired(const account_t *acc) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  return false;
}

void account_set_unban_time(account_t *acc, time_t t) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) t;
}

void account_set_expiration_time(account_t *acc, time_t t) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) t;
}

void account_set_email(account_t *acc, const char *new_email) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) new_email;
}

bool account_print_summary(const account_t *acct, int fd) {
  // remove the contents of this function and replace it with your own code.
  (void) acct;
  (void) fd;
  return false;
}

