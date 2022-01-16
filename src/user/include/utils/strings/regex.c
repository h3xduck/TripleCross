#include <regex.h>
#include <stdio.h>
#include <stdlib.h>

#include "regex.h"

/**
 * @brief Compares string against regular expression for file descriptor detection
 * 
 * @param str
 * @return 0 if matches, 1 if not matching, -1 if error
 */
int regex_match_fd(const char* str){
    regex_t regex;
    int reti;

    // Compile regular expression (/proc/*/fd/*)
    reti = regcomp(&regex, "^\\/proc\\/[[:alnum:]]\\+\\/fd\\/[^\n ]\\+$", 0);
    if (reti) {
        fprintf(stderr, "Could not compile regex\n");
        return -1;
    }

    // Execute regular expression
    int result = 0;
    reti = regexec(&regex, str, 0, NULL, 0);
    if (!reti) {
        puts("Match");
        result = 0;
    }else if (reti == REG_NOMATCH) {
        result = 1;
    }else {
        char msgbuf[100];
        regerror(reti, &regex, msgbuf, sizeof(msgbuf));
        fprintf(stderr, "Regex match failed: %s\n", msgbuf);
        return -1;
    }

    //Free memory allocated to the pattern buffer by regcomp()
    regfree(&regex);

    return result;
}
