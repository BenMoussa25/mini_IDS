#ifndef UTILS_H
#define UTILS_H

// Log an alert to file and console (red timestamp)
void log_alert(const char *format, ...);

// Log IPS actions (yellow/magenta/green based on action type)
void log_action(const char *action, const char *ip_address);

// Log system events (cyan)
void log_event(const char *format, ...);

#endif
