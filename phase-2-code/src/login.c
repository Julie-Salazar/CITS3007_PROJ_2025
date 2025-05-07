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

#define SESSION_DURATION (3600 * 24)  // 24-hour session duration
#define MAX_FAILED_ATTEMPTS 5         // Maximum number of failed attempts
#define BAN_DURATION (3600 * 24)      // Ban duration (24 hours)
#define RATE_LIMIT_WINDOW 60          // Rate limit window (60 seconds)
#define MAX_ATTEMPTS_PER_WINDOW 10    // Maximum attempts per window
#define IP_TRACKING_SIZE 1000         // Size of IP tracking array
#define MIN_PASSWORD_LENGTH 8         // Minimum password length
#define MAX_PASSWORD_LENGTH 128       // Maximum password length
#define MAX_USERID_LENGTH 64          // Maximum user ID length

// IP tracking structure
typedef struct {
    ip4_addr_t ip;
    unsigned int fail_count;          // Number of failures
    time_t last_attempt;             // Time of last attempt
    unsigned int window_attempts;     // Attempts in current window
    time_t window_start;             // Start time of current window
} ip_tracking_t;

// Static array for IP tracking
static ip_tracking_t ip_tracking[IP_TRACKING_SIZE] = {0};

// Generate random session ID using cryptographically secure random number generator
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
static bool is_valid_password(const char *password) {
    if (!password) return false;

    size_t len = strlen(password);
    return len >= 6 && len <= MAX_PASSWORD_LENGTH;
}

// Check if rate limited with improved tracking
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
