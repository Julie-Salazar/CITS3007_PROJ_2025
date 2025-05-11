#define _POSIX_C_SOURCE 199309L

#include "login.h"
#include "db.h"
#include "logging.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <openssl/rand.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>

/**
 * @file login.c
 * @brief Implements user login flow, session handling, and basic IP-based security mechanisms.
 *
 * Handles account lookup, password validation, IP rate limiting, and ban logic.
 * Also responsible for generating session IDs using secure random data.
 */
#define SESSION_DURATION (3600 * 24)  // 24-hour session duration
#define MAX_FAILED_ATTEMPTS 5         // Maximum number of failed attempts
#define BAN_DURATION (3600 * 24)      // Ban duration (24 hours)
#define RATE_LIMIT_WINDOW 60          // Rate limit window (60 seconds)
#define MAX_ATTEMPTS_PER_WINDOW 10    // Maximum attempts per window
#define IP_TRACKING_SIZE 1000         // Size of IP tracking array
#define MIN_PASSWORD_LENGTH 8         // Minimum password length
#define MAX_PASSWORD_LENGTH 128       // Maximum password length
#define MAX_USERID_LENGTH 64          // Maximum user ID length

/**
 * @struct ip_tracking_t
 * @brief Tracks state for login attempts from a specific IPv4 address.
 *
 * Used to implement rate limiting and temporary bans based on repeated failures.
 */
typedef struct {
    ip4_addr_t ip;
    unsigned int fail_count;          // Number of failures
    time_t last_attempt;             // Time of last attempt
    unsigned int window_attempts;     // Attempts in current window
    time_t window_start;             // Start time of current window
} ip_tracking_t;

// Static array for IP tracking
static ip_tracking_t ip_tracking[IP_TRACKING_SIZE] = {0};

/**
 * @brief Generates a cryptographically secure session ID.
 *
 * Fills a given buffer with a 64-character hexadecimal string derived from 32 bytes
 * of secure random data using OpenSSL RAND_bytes().
 *
 * @param session_id Output buffer (must be at least 65 bytes to include null terminator).
 * @param length Size of the session_id buffer.
 * @return true if generation succeeded, false on failure.
 */
static bool generate_session_id(char *session_id, size_t length) {
    if (!session_id || length < 33) {  // Ensure minimum length for security
        return false;
    }

    unsigned char random_bytes[32];
    if (RAND_bytes(random_bytes, sizeof(random_bytes)) != 1) {
        log_message(LOG_ERROR, "Failed to generate secure random bytes for session ID");
        return false;
    }
    
    for (size_t i = 0; i < sizeof(random_bytes); i++) {
    snprintf(session_id + (i * 2), 3, "%02x", random_bytes[i]);
}
    session_id[64] = '\0';

    return true;
}

// Validate user ID format
/**
 * @brief Checks whether a given user ID string is valid.
 *
 * Only alphanumeric characters and underscores are allowed. Rejects IDs
 * that are empty or exceed MAX_USERID_LENGTH.
 *
 * @param userid Null-terminated user ID string.
 * @return true if valid, false otherwise.
 */
static bool is_valid_userid(const char *userid) {
    if (!userid) return false;
    
    size_t len = strlen(userid);
    if (len == 0 || len > MAX_USERID_LENGTH) return false;
    
    // Check for valid characters (alphanumeric and underscore only)
    for (size_t i = 0; i < len; i++) {
        if (!isalnum((unsigned char)userid[i]) && userid[i] != '_') {
            return false;
        }
    }
    return true;
}

// Validate password format
/**
 * @brief Verifies password length constraints.
 *
 * Accepts passwords between 6 and MAX_PASSWORD_LENGTH characters.
 * No character content validation is performed here.
 *
 * @param password Null-terminated password string.
 * @return true if password length is within bounds, false otherwise.
 */
static bool is_valid_password(const char *password) {
    if (!password) return false;

    size_t len = strlen(password);
    return len >= 6 && len <= MAX_PASSWORD_LENGTH;
}

// Check if rate limited with improved tracking
/**
 * @brief Determines if the specified IP has exceeded the allowed login rate.
 *
 * Checks whether the number of attempts in the current time window exceeds
 * MAX_ATTEMPTS_PER_WINDOW. If the IP is new or its window has expired,
 * the counters are reset.
 *
 * @param ip The IPv4 address to check.
 * @return true if rate limit has been exceeded, false otherwise.
 */
static bool is_rate_limited(ip4_addr_t ip) {
    if (ip == 0) return true;  // Invalid IP
    
    time_t current_time = time(NULL);
    if (current_time == (time_t)-1) {
        log_message(LOG_ERROR, "Failed to get current time for rate limiting");
        return true;  // Fail safe
    }
    
    for (int i = 0; i < IP_TRACKING_SIZE; i++) {
        if (ip_tracking[i].ip == ip) {
            // Reset counter if current window has expired
            if (current_time - ip_tracking[i].window_start >= RATE_LIMIT_WINDOW) {
                ip_tracking[i].window_attempts = 0;
                ip_tracking[i].window_start = current_time;
            }
            
            // Check if rate limit exceeded
            if (ip_tracking[i].window_attempts >= MAX_ATTEMPTS_PER_WINDOW) {
                log_message(LOG_WARN, "Rate limit exceeded for IP %u", ip);
                return true;
            }
            
            ip_tracking[i].window_attempts++;
            return false;
        } else if (ip_tracking[i].ip == 0) {
            // New IP
            ip_tracking[i].ip = ip;
            ip_tracking[i].window_attempts = 1;
            ip_tracking[i].window_start = current_time;
            return false;
        }
    }
    
    // If we get here, the tracking array is full
    log_message(LOG_ERROR, "IP tracking array full");
    return true;  // Fail safe
}

// Check if IP is banned with improved tracking
/**
 * @brief Checks whether the given IP address is currently banned.
 *
 * If the IP has failed more than MAX_FAILED_ATTEMPTS within BAN_DURATION,
 * it is considered temporarily banned.
 *
 * @param ip IPv4 address to check.
 * @return true if the IP is banned, false otherwise.
 */
static bool is_ip_banned(ip4_addr_t ip) {
    if (ip == 0) return true;  // Invalid IP
    
    time_t current_time = time(NULL);
    if (current_time == (time_t)-1) {
        log_message(LOG_ERROR, "Failed to get current time for IP ban check");
        return true;  // Fail safe
    }
    
    for (int i = 0; i < IP_TRACKING_SIZE; i++) {
        if (ip_tracking[i].ip == ip) {
            if (ip_tracking[i].fail_count >= MAX_FAILED_ATTEMPTS) {
                if (current_time - ip_tracking[i].last_attempt < BAN_DURATION) {
                    log_message(LOG_WARN, "IP %u is banned", ip);
                    return true;
                } else {
                    // Reset counter after ban duration
                    ip_tracking[i].fail_count = 0;
                    log_message(LOG_INFO, "IP %u ban expired", ip);
                }
            }
            return false;
        }
    }
    return false;
}

// Record IP failure with improved tracking
/**
 * @brief Logs a failed login attempt for a given IP.
 *
 * Increments the IP’s failure counter and updates the timestamp.
 * Used for ban enforcement.
 *
 * @param ip The IPv4 address associated with the failed login.
 */
static void record_ip_failure(ip4_addr_t ip) {
    if (ip == 0) return;  // Invalid IP
    
    time_t current_time = time(NULL);
    if (current_time == (time_t)-1) {
        log_message(LOG_ERROR, "Failed to get current time for IP failure recording");
        return;
    }
    
    for (int i = 0; i < IP_TRACKING_SIZE; i++) {
        if (ip_tracking[i].ip == ip || ip_tracking[i].ip == 0) {
            ip_tracking[i].ip = ip;
            ip_tracking[i].fail_count++;
            ip_tracking[i].last_attempt = current_time;
            log_message(LOG_WARN, "Recorded login failure for IP %u (count: %u)", 
                       ip, ip_tracking[i].fail_count);
            break;
        }
    }
}

// Add variable security delay to prevent timing attacks
/**
 * @brief Introduces a small randomized delay to hinder brute-force attacks.
 *
 * Adds 100–200ms of delay using nanosleep() with a random value from RAND_bytes().
 * This helps mitigate timing-based attacks and user enumeration.
 */
static void add_security_delay(void) {
    unsigned char random_delay;
    if (RAND_bytes(&random_delay, 1) != 1) {
        random_delay = 100;  // Fallback delay
    }
    
    struct timespec delay = {
        .tv_sec = 0,
        .tv_nsec = (100000000 + (random_delay * 1000000))  // 100-200ms
    };
    nanosleep(&delay, NULL);
}

/**
 * @brief Attempts to authenticate a user and establish a login session.
 *
 * This function verifies credentials, enforces IP-based rate limiting and bans,
 * checks account state (banned/expired), and if successful, generates a session.
 *
 * @param userid The username attempting to log in.
 * @param password The plaintext password to validate.
 * @param client_ip The client’s IPv4 address.
 * @param login_time The time at which the login was initiated.
 * @param client_output_fd Optional file descriptor for client response (not used here).
 * @param[out] session Output session data structure if login is successful.
 * @return login_result_t indicating success or the reason for failure.
 */
login_result_t handle_login(const char *userid, const char *password,
                          ip4_addr_t client_ip, time_t login_time,
                          int client_output_fd,
                          login_session_data_t *session) 
{
  
    (void)client_output_fd;
    
    // Parameter validation
    if (!userid || !password || !session) {
        log_message(LOG_ERROR, "Login attempt failed: Invalid parameters");
        return LOGIN_FAIL_INTERNAL_ERROR;
    }

    // Validate user ID format
    if (!is_valid_userid(userid)) {
        log_message(LOG_WARN, "Login attempt failed: Invalid user ID format");
        return LOGIN_FAIL_INTERNAL_ERROR;
    }

    // Validate password format
    if (!is_valid_password(password)) {
        log_message(LOG_WARN, "Login attempt failed: Invalid password format");
        return LOGIN_FAIL_INTERNAL_ERROR;
    }

    // Check rate limiting
    if (is_rate_limited(client_ip)) {
        log_message(LOG_WARN, "Login attempt rate limited for IP %u", client_ip);
        return LOGIN_FAIL_IP_BANNED;
    }

    // Check if IP is banned
    if (is_ip_banned(client_ip)) {
        log_message(LOG_WARN, "Login attempt from banned IP %u", client_ip);
        return LOGIN_FAIL_IP_BANNED;
    }

    // Look up user account
    account_t account;
    if (!account_lookup_by_userid(userid, &account)) {
        add_security_delay(); // Prevent user enumeration
        log_message(LOG_WARN, "Login attempt failed: User '%s' not found", userid);
        record_ip_failure(client_ip);
        return LOGIN_FAIL_USER_NOT_FOUND;
    }

    // Check account status
    if (account_is_banned(&account)) {
        log_message(LOG_WARN, "Login attempt failed: Account '%s' is banned", userid);
        return LOGIN_FAIL_ACCOUNT_BANNED;
    }

    if (account_is_expired(&account)) {
        log_message(LOG_WARN, "Login attempt failed: Account '%s' has expired", userid);
        return LOGIN_FAIL_ACCOUNT_EXPIRED;
    }

    // Validate password
    if (!account_validate_password(&account, password)) {
        add_security_delay(); // Prevent password brute-force
        log_message(LOG_WARN, "Login attempt failed: Invalid password for user '%s'", userid);
        account_record_login_failure(&account);
        record_ip_failure(client_ip);
        return LOGIN_FAIL_BAD_PASSWORD;
    }

    // Login successful, create session
    account_record_login_success(&account, client_ip);
    session->account_id = account.account_id;
    session->session_start = login_time;
    session->expiration_time = login_time + SESSION_DURATION;

    // Generate random session ID
    char session_id[65];
    if (!generate_session_id(session_id, sizeof(session_id))) {
        log_message(LOG_ERROR, "Failed to generate session ID for user '%s'", userid);
        return LOGIN_FAIL_INTERNAL_ERROR;
    }

    log_message(LOG_INFO, "Successful login for user '%s' from IP %u", userid, client_ip);
    return LOGIN_SUCCESS;

}



