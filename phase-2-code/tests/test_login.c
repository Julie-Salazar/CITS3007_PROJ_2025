#include "login.h"
#include "account.h"
#include "logging.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <unistd.h>


//Test case structure
typedef struct {
    const char *test_name;
    const char *userid;
    const char *password;
    ip4_addr_t client_ip;
    login_result_t expected_result;
} test_case_t;


// Demo account data
static account_t test_accounts[] = {
    {
        .userid = "testuser1",
        .password_hash = "hashed_password1",
        .email = "test1@example.com",
        .birthdate = "1990-01-01",
        .account_id = 1,
        .unban_time = 0,
        .expiration_time = 0,
        .login_count = 0,
        .login_fail_count = 0,
        .last_login_time = 0,
        .last_ip = 0
    },
    {
        .userid = "banned_user",
        .password_hash = "hashed_password2",
        .email = "test2@example.com",
        .birthdate = "1990-01-01",
        .account_id = 2,
        .unban_time = 0,  
        .expiration_time = 0,
        .login_count = 0,
        .login_fail_count = 0,
        .last_login_time = 0,
        .last_ip = 0
    },
    {
        .userid = "expired_user",
        .password_hash = "hashed_password3",
        .email = "test3@example.com",
        .birthdate = "1990-01-01",
        .account_id = 3,
        .unban_time = 0,
        .expiration_time = 0,  
        .login_count = 0,
        .login_fail_count = 0,
        .last_login_time = 0,
        .last_ip = 0
    }
};


// Initialize the test account

static void init_test_accounts(void) {
    time_t now = time(NULL);
    test_accounts[1].unban_time = now + 3600;  
    test_accounts[2].expiration_time = now - 3600;  
}

// Simulation account search function
bool account_lookup_by_userid(const char *userid, account_t *account) {
    for (size_t i = 0; i < sizeof(test_accounts) / sizeof(test_accounts[0]); i++) {
        if (strcmp(test_accounts[i].userid, userid) == 0) {
            memcpy(account, &test_accounts[i], sizeof(account_t));
            return true;
        }
    }
    return false;
}


//Simulate password verification function
bool account_validate_password(const account_t *account, const char *password) {
    (void)account;  
    return strcmp(password, "correct_password") == 0;
}

//test case
static test_case_t test_cases[] = {
    {
        "Valid login",
        "testuser1",
        "correct_password",
        0x7f000001, // 127.0.0.1
        LOGIN_SUCCESS
    },
    {
        "Invalid userid",
        "nonexistent_user",
        "correct_password",
        0x7f000001,
        LOGIN_FAIL_USER_NOT_FOUND
    },
    {
        "Invalid password",
        "testuser1",
        "wrong_password",
        0x7f000001,
        LOGIN_FAIL_BAD_PASSWORD
    },
    {
        "Banned account",
        "banned_user",
        "correct_password",
        0x7f000001,
        LOGIN_FAIL_ACCOUNT_BANNED
    },
    {
        "Expired account",
        "expired_user",
        "correct_password",
        0x7f000001,
        LOGIN_FAIL_ACCOUNT_EXPIRED
    },
    {
        "NULL parameters",
        NULL,
        "correct_password",
        0x7f000001,
        LOGIN_FAIL_INTERNAL_ERROR
    }
};


static void run_test_case(const test_case_t *test) {
    printf("Running test: %s\n", test->test_name);
    
    login_session_data_t session;
    login_result_t result = handle_login(
        test->userid,
        test->password,
        test->client_ip,
        time(NULL),
        1,  
        &session
    );
    
    if (result == test->expected_result) {
        printf("Test PASSED\n");
    } else {
        printf("Test FAILED: Expected %d, got %d\n", test->expected_result, result);
    }
    printf("----------------------------------------\n");
}


int main(void) {
   
    init_test_accounts();
    
    printf("Starting login system tests...\n");
    printf("----------------------------------------\n");
    
   
    for (size_t i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
        run_test_case(&test_cases[i]);
    }
    
    printf("All tests completed\n");
    return 0;
} 
