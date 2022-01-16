#ifndef __REGEX_H
#define __REGEX_H

/**
 * @brief Compares string against regular expression for file descriptor detection
 * 
 * @param str
 * @return 0 if matches, 1 if not matching, -1 if error
 */
int regex_match_fd(const char* str);

#endif