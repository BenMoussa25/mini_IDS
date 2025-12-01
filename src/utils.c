#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <string.h>

// Get formatted timestamp
static void get_timestamp(char *buffer, size_t size) {
    time_t now = time(NULL);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", localtime(&now));
}

// Log detection alerts (red timestamp)
void log_alert(const char *format, ...) {
    FILE *f = fopen("logs/alerts.log", "a");
    if (!f) return;

    char timestr[64];
    get_timestamp(timestr, sizeof(timestr));

    fprintf(f, "[%s] ", timestr);
    printf("\033[1;31m[%s]\033[0m ", timestr);

    va_list args, args2;
    va_start(args, format);
    va_copy(args2, args);
    
    vfprintf(f, format, args);
    vprintf(format, args2);
    
    va_end(args);
    va_end(args2);

    fprintf(f, "\n");
    printf("\n");
    fflush(stdout);
    fclose(f);
}

// Log IPS actions (BLOCKED/REJECTED/UNBLOCKED)
void log_action(const char *action, const char *ip_address) {
    FILE *f = fopen("logs/alerts.log", "a");
    if (!f) return;

    char timestr[64];
    get_timestamp(timestr, sizeof(timestr));

    // Determine color based on action type
    const char *color;
    if (strcmp(action, "BLOCKED") == 0) {
        color = "\033[1;33m";  // Yellow for BLOCKED
    } else if (strcmp(action, "REJECTED") == 0) {
        color = "\033[1;35m";  // Magenta for REJECTED
    } else if (strcmp(action, "UNBLOCKED") == 0) {
        color = "\033[1;32m";  // Green for UNBLOCKED
    } else {
        color = "\033[1;36m";  // Cyan for other actions
    }

    // Write to log file (plain text, no colors)
    fprintf(f, "[%s] [IPS] %s: %s\n", timestr, action, ip_address);
    
    // Print to console with color - colored timestamp and [IPS] tag
    printf("%s[%s]\033[0m %s[IPS]\033[0m %s: %s\n", 
           color, timestr, color, action, ip_address);
    fflush(stdout);
    fclose(f);
}

// Log system events (startup, shutdown, errors)
void log_event(const char *format, ...) {
    FILE *f = fopen("logs/alerts.log", "a");
    if (!f) return;

    char timestr[64];
    get_timestamp(timestr, sizeof(timestr));

    fprintf(f, "[%s] [SYSTEM] ", timestr);
    printf("\033[1;36m[%s]\033[0m \033[1;36m[SYSTEM]\033[0m ", timestr);

    va_list args, args2;
    va_start(args, format);
    va_copy(args2, args);
    
    vfprintf(f, format, args);
    vprintf(format, args2);
    
    va_end(args);
    va_end(args2);

    fprintf(f, "\n");
    printf("\n");
    fflush(stdout);
    fclose(f);
}