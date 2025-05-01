#include "account.h"


account_t *account_create(const char *userid, const char *plaintext_password,
                          const char *email, const char *birthdate
                      )
{
  if (userid == NULL || plaintext_password == NULL || email == NULL || birthdate == NULL) { // check for NULL arguments
    log_message("account_create: NULL argument");
    return NULL;
  }

size_t userid_len = 0;
for (userid_len = 0; userid_len < USER_ID_LENGTH && userid[userid_len] != '\0'; userid_len++); // find the length of the user ID
  if (userid_len == 0 || userid_len >= USER_ID_LENGTH) { // check for empty or too long user ID
    log_message("account_create: Invalid user ID length");
    return NULL;
  }

  if (userid[0] == ' ') { // check for leading spaces
    log_message("account_create: User ID cannot start with a space");
    return NULL;
  }

  if (userid[userid_len - 1] == ' ') { // check for trailing spaces
    log_message("account_create: User ID cannot end with a space");
    return NULL;
  }

if (userid[userid_len] == ' ') {//check for inbetween spaces
    log_message("account_create: User ID contains spaces");
    return NULL;
  }

  //email validation checking that it contains an '@' and a '.' and that the '@' comes before the '.'
  size_t email_len = 0;
  for (email_len = 0; email_len < EMAIL_LENGTH && email[email_len] != '\0'; email_len++); // find the length of the email
  
  if (email_len == 0 || email_len >= EMAIL_LENGTH) { // check for empty or too long email
    log_message("account_create: Invalid email length");
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

  //valaidate birthdate in format YYYY-MM-DD

  if (strlen(birthdate) != 10 || 
  birthdate[4] != '-' || 
  birthdate[7] != '-') {
  log_message("Error: Invalid birthdate format, must be YYYY-MM-DD");
  return NULL;
}
  




}




void account_free(account_t *acc) { // free memory and resources used by the account
  if (acc != NULL){
    memset(acc->password_hash, 0, HASH_LENGTH);// clear the password hash

    free(acc);// free the account structure
  }
}


bool account_validate_password(const account_t *acc, const char *plaintext_password) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) plaintext_password;
  return false;
}

bool account_update_password(account_t *acc, const char *new_plaintext_password) {
  // remove the contents of this function and replace it with your own code.
  (void) acc;
  (void) new_plaintext_password;
  return false;
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

