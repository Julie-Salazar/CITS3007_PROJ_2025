#include "login.h"
#include "db.h"
#include "logging.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <openssl/rand.h>

#define SESSION_DURATION (3600 * 24)  // 24-hour session duration
#define MAX_FAILED_ATTEMPTS 5         // Maximum number of failed attempts
#define BAN_DURATION (3600 * 24)      // Ban duration (24 hours)
#define RATE_LIMIT_WINDOW 60          // Rate limit window (60 seconds)
#define MAX_ATTEMPTS_PER_WINDOW 10    // Maximum attempts per window
#define IP_TRACKING_SIZE 1000         // Size of IP tracking array
#define MIN_PASSWORD_LENGTH 8         // Minimum password length

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

// Generate random session ID
static void generate_session_id(char *session_id, size_t length) {
    unsigned char random_bytes[32];
    RAND_bytes(random_bytes, sizeof(random_bytes));
    
    for(size_t i = 0; i < length - 1; i++) {
        sprintf(session_id + (i * 2), "%02x", random_bytes[i % sizeof(random_bytes)]);
    }
    session_id[length - 1] = '\0';
}

// Check if rate limited
static bool is_rate_limited(ip4_addr_t ip) {
    time_t current_time = time(NULL);
    
    for (int i = 0; i < IP_TRACKING_SIZE; i++) {
        if (ip_tracking[i].ip == ip) {
            // Reset counter if current window has expired
            if (current_time - ip_tracking[i].window_start >= RATE_LIMIT_WINDOW) {
                ip_tracking[i].window_attempts = 0;
                ip_tracking[i].window_start = current_time;
            }
            
            // Check if rate limit exceeded
            if (ip_tracking[i].window_attempts >= MAX_ATTEMPTS_PER_WINDOW) {
                return true;
            }
            
            ip_tracking[i].window_attempts++;
            break;
        } else if (ip_tracking[i].ip == 0) {
            // New IP
            ip_tracking[i].ip = ip;
            ip_tracking[i].window_attempts = 1;
            ip_tracking[i].window_start = current_time;
            break;
        }
    }
    return false;
}

// Check if IP is banned
static bool is_ip_banned(ip4_addr_t ip) {
    time_t current_time = time(NULL);
    
    for (int i = 0; i < IP_TRACKING_SIZE; i++) {
        if (ip_tracking[i].ip == ip) {
            if (ip_tracking[i].fail_count >= MAX_FAILED_ATTEMPTS) {
                // Check if within ban period
                if (current_time - ip_tracking[i].last_attempt < BAN_DURATION) {
                    return true;
                } else {
                    // Reset counter
                    ip_tracking[i].fail_count = 0;
                }
            }
            break;
        }
    }
    return false;
}

// Record IP failure attempt
static void record_ip_failure(ip4_addr_t ip) {
    time_t current_time = time(NULL);
    
    for (int i = 0; i < IP_TRACKING_SIZE; i++) {
        if (ip_tracking[i].ip == ip || ip_tracking[i].ip == 0) {
            ip_tracking[i].ip = ip;
            ip_tracking[i].fail_count++;
            ip_tracking[i].last_attempt = current_time;
            break;
        }
    }
}

// Add delay to prevent timing attacks
static void add_security_delay(void) {
    struct timespec delay = {0, 100000000}; // 100ms
    nanosleep(&delay, NULL);
}

login_result_t handle_login(const char *userid, const char *password,
                            ip4_addr_t client_ip, time_t login_time,
                            int client_output_fd,
                            login_session_data_t *session) 
{
<<<<<<< HEAD
    // Parameter validation
    if (!userid || !password || !session) {
        dprintf(log_fd, "Login attempt failed: Invalid parameters\n");
        return LOGIN_FAIL_INTERNAL_ERROR;
    }
=======
  // remove the contents of this function and replace it with your own code.
  (void) userid;
  (void) password;
  (void) client_ip;
  (void) login_time;
  (void) client_output_fd;
  (void) session;
>>>>>>> 2b2df3a4a12237db8e9f8e5469671391bb0a825b

    // Basic input validation
    if (strlen(userid) == 0 || strlen(password) < MIN_PASSWORD_LENGTH) {
        dprintf(log_fd, "Login attempt failed: Invalid input length\n");
        return LOGIN_FAIL_INTERNAL_ERROR;
    }

    // Check rate limiting
    if (is_rate_limited(client_ip)) {
        dprintf(client_output_fd, "Login failed: Too many attempts. Please try again later.\n");
        dprintf(log_fd, "Login attempt rate limited for IP %u\n", client_ip);
        return LOGIN_FAIL_IP_BANNED;
    }

    // Check if IP is banned
    if (is_ip_banned(client_ip)) {
        dprintf(client_output_fd, "Login failed: Too many failed attempts from this IP\n");
        dprintf(log_fd, "Login attempt from banned IP %u\n", client_ip);
        return LOGIN_FAIL_IP_BANNED;
    }

    // Look up user account
    account_t account;
    if (!account_lookup_by_userid(userid, &account)) {
        add_security_delay(); // Prevent user enumeration
        dprintf(client_output_fd, "Login failed: Invalid credentials\n");
        dprintf(log_fd, "Login attempt failed: User '%s' not found\n", userid);
        record_ip_failure(client_ip);
        return LOGIN_FAIL_USER_NOT_FOUND;
    }

    // Check account status
    if (account_is_banned(&account)) {
        dprintf(client_output_fd, "Login failed: Account is banned\n");
        dprintf(log_fd, "Login attempt failed: Account '%s' is banned\n", userid);
        return LOGIN_FAIL_ACCOUNT_BANNED;
    }

    if (account_is_expired(&account)) {
        dprintf(client_output_fd, "Login failed: Account has expired\n");
        dprintf(log_fd, "Login attempt failed: Account '%s' has expired\n", userid);
        return LOGIN_FAIL_ACCOUNT_EXPIRED;
    }

    // Validate password
    if (!account_validate_password(&account, password)) {
        add_security_delay(); // Prevent password brute-force
        dprintf(client_output_fd, "Login failed: Invalid credentials\n");
        dprintf(log_fd, "Login attempt failed: Invalid password for user '%s'\n", userid);
        account_record_login_failure(&account);
        record_ip_failure(client_ip);
        return LOGIN_FAIL_BAD_PASSWORD;
    }

    // Login successful, create session
    account_record_login_success(&account, client_ip);
    session->account_id = account.account_id;
    session->session_start = login_time;
    session->expiration_time = login_time + SESSION_DURATION;

    // Generate random session ID (if needed)
    char session_id[65];
    generate_session_id(session_id, sizeof(session_id));

    dprintf(client_output_fd, "Login successful. Welcome, %s!\n", userid);
    dprintf(log_fd, "Successful login for user '%s' from IP %u\n", userid, client_ip);

    return LOGIN_SUCCESS;
}
