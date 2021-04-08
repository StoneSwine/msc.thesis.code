#ifndef MISC_SNORT_FUNCS_H
#define MISC_SNORT_FUNCS_H

#include "signature.h"

void mSplitFree(char ***pbuf, int num_toks);
char *mSplitAddTok(const char *str, const int len, const char *sep_chars, const char meta_char);
char **mSplit(const char *str, const char *sep_chars, const int max_toks, int *num_toks, const char meta_char);


#endif