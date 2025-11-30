#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <string.h>

void log_alert(const char *format, ...) {
    FILE *f = fopen("logs/alerts.log", "a");
    if (!f) return;

    time_t now = time(NULL);
    char timestr[64];
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(f, "[%s] ", timestr);
    printf("\033[1;31m[%s] ALERT: \033[0m", timestr);

    va_list args, args2;
    va_start(args, format);
    va_copy(args2, args);  // Need to copy for second use
    
    vfprintf(f, format, args);
    vprintf(format, args2);
    
    va_end(args);
    va_end(args2);

    fprintf(f, "\n");
    printf("\n");
    fflush(stdout);  // Force output
    fclose(f);
}