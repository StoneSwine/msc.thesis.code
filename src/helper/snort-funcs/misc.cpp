
#include <iostream>
#include "signature.h"
#include <cstring>
#include <cstdio>
#include "parser.h"
#include "misc.h"

/****************************************************************
 *
 * Free the buffer allocated by mSplit().
 *
 * char** toks = NULL;
 * int num_toks = 0;
 * toks = (str, " ", 2, &num_toks, 0);
 * mSplitFree(&toks, num_toks);
 *
 * At this point, toks is again NULL.
 *
 ****************************************************************/
void mSplitFree(char ***pbuf, int num_toks) {
  int i;
  char **buf; /* array of string pointers */

  if (pbuf == NULL || *pbuf == NULL) {
    return;
  }

  buf = *pbuf;

  for (i = 0; i < num_toks; i++) {
    if (buf[i] != NULL) {
      free(buf[i]);
      buf[i] = NULL;
    }
  }

  free(buf);
  *pbuf = NULL;
}

/* Will not return NULL.  SnortAlloc will fatal if it fails */
char *mSplitAddTok(const char *str, const int len, const char *sep_chars, const char meta_char) {
  size_t i, j, k;
  char *tok;
  int tok_len = 0;
  int got_meta = 0;
  size_t sep_length = strlen(sep_chars);

  /* Get the length of the returned tok
   * Could have a maximum token length and use a fixed sized array and
   * fill it in as we go but don't want to put on that constraint */
  for (i = 0; (int) i < len; i++) {
    if (!got_meta) {
      if (str[i] == meta_char) {
        got_meta = 1;
        continue;
      }
    } else {
      /* See if the current character is a separator */
      for (j = 0; j < sep_length; j++) {
        if (str[i] == sep_chars[j])
          break;
      }

      /* It's a non-separator character, so include
       * the meta character in the return tok */
      if (j == sep_length)
        tok_len++;

      got_meta = 0;
    }

    tok_len++;
  }

  /* Allocate it and fill it in */
  tok = (char *) calloc(tok_len + 1, sizeof(char));
  for (i = 0, k = 0; (int) i < len; i++) {
    if (!got_meta) {
      if (str[i] == meta_char) {
        got_meta = 1;
        continue;
      }
    } else {
      /* See if the current character is a separator */
      for (j = 0; j < sep_length; j++) {
        if (str[i] == sep_chars[j])
          break;
      }

      /* It's a non-separator character, so include
       * the meta character in the return tok */
      if (j == sep_length)
        tok[k++] = meta_char;

      got_meta = 0;
    }

    tok[k++] = str[i];
  }

  return tok;
}

/****************************************************************
 *
 * Function: mSplit()
 *
 * Purpose: Splits a string into tokens non-destructively.
 *
 * Parameters:
 *  char *
 *      The string to be split
 *  char *
 *      A string of token seperaters
 *  int
 *      The maximum number of tokens to be returned. A value
 *      of 0 means to get them all.
 *  int *
 *      Place to store the number of tokens returned
 *  char
 *      The "escape metacharacter", treat the character after
 *      this character as a literal and "escape" a seperator.
 *
 *  Note if max_toks is reached, the last tok in the returned
 *  token array will possibly have separator characters in it.
 *
 *  Returns:
 *      2D char array with one token per "row" of the returned
 *      array.
 *
 ****************************************************************/
char **mSplit(const char *str, const char *sep_chars, const int max_toks, int *num_toks, const char meta_char) {
  size_t cur_tok = 0; /* current token index into array of strings */
  size_t tok_start;   /* index to start of token */
  size_t i, j;
  int escaped = 0;
  /* It's rare we'll need more than this even if max_toks is set really
   * high.  Store toks here until finished, then allocate.  If more than
   * this is necessary, then allocate max toks */
  char *toks_buf[TOKS_BUF_SIZE];
  size_t toks_buf_size = TOKS_BUF_SIZE;
  int toks_buf_size_increment = 10;
  char **toks_alloc = NULL; /* Used if the static buf isn't enough */
  char **toks = toks_buf;   /* Pointer to one of the two above */
  char **retstr;
  char *whitespace = " \t";
  size_t str_length, sep_length;

  // assert(num_toks);

  *num_toks = 0;

  if (str == NULL)
    return NULL;

  str_length = strlen(str);

  if (str_length == 0)
    return NULL;

  if (sep_chars == NULL)
    sep_chars = whitespace;

  sep_length = strlen(sep_chars);

  if (sep_length == 0)
    return NULL;

  /* Meta char cannot also be a separator char */
  for (i = 0; i < sep_length; i++) {
    if (sep_chars[i] == meta_char)
      return NULL;
  }

  /* Move past initial separator characters and whitespace */
  for (i = 0; i < str_length; i++) {
    if (isspace((int) str[i]))
      continue;

    for (j = 0; j < sep_length; j++) {
      if (str[i] == sep_chars[j])
        break;
    }

    /* Not a separator character or whitespace */
    if (j == sep_length)
      break;
  }

  if (i == str_length) {
    /* Nothing but separator characters or whitespace in string */
    return NULL;
  }

  /* User only wanted one tok so return the rest of the string in
   * one tok */
  if ((cur_tok + 1) == (size_t) max_toks) {
    retstr = (char **) calloc(sizeof(char *), sizeof(char));
    retstr[cur_tok] = strndup(&str[i], str_length - i);
    if (retstr[cur_tok] == NULL) {
      mSplitFree(&retstr, cur_tok + 1);
      return NULL;
    }

    *num_toks = cur_tok + 1;
    return retstr;
  }

  /* Mark the beginning of the next tok */
  tok_start = i;
  for (; i < str_length; i++) {
    if (!escaped) {
      /* Got an escape character.  Don't include it now, but
       * must be a character after it. */
      if (str[i] == meta_char) {
        escaped = 1;
        continue;
      }

      /* See if the current character is a separator */
      for (j = 0; j < sep_length; j++) {
        if (str[i] == sep_chars[j])
          break;
      }

      /* It's a normal character */
      if (j == sep_length)
        continue;

      /* Current character matched a separator character.  Trim off
       * whitespace previous to the separator.  If we get here, there
       * is at least one savable character */
      for (j = i; j > tok_start; j--) {
        if (!isspace((int) str[j - 1]))
          break;
      }

      /* Allocate a buffer.  The length will not have included the
       * meta char of escaped separators */
      toks[cur_tok] = mSplitAddTok(&str[tok_start], j - tok_start, sep_chars, meta_char);

      /* Increment current token index */
      cur_tok++;

      /* Move past any more separator characters or whitespace */
      for (; i < str_length; i++) {
        if (isspace((int) str[i]))
          continue;

        for (j = 0; j < sep_length; j++) {
          if (str[i] == sep_chars[j])
            break;
        }

        /* Not a separator character or whitespace */
        if (j == sep_length)
          break;
      }

      /* Nothing but separator characters or whitespace left in the string */
      if (i == str_length) {
        *num_toks = cur_tok;

        if (toks != toks_alloc) {
          retstr = (char **) calloc(sizeof(char *) * cur_tok, sizeof(char));
          memcpy(retstr, toks, (sizeof(char *) * cur_tok));
        } else {
          retstr = toks;
        }

        return retstr;
      }

      /* Reached the size of our current string buffer and need to
       * allocate something bigger.  Only get here once if max toks
       * set to something other than 0 because we'll just allocate
       * max toks in that case. */
      if (cur_tok == toks_buf_size) {
        char **tmp;

        if (toks_alloc != NULL)
          tmp = toks_alloc;
        else
          tmp = toks_buf;

        if (max_toks != 0)
          toks_buf_size = max_toks;
        else
          toks_buf_size = cur_tok + toks_buf_size_increment;

        toks_alloc = (char **) calloc(sizeof(char *) * toks_buf_size, sizeof(char));
        memcpy(toks_alloc, tmp, (sizeof(char *) * cur_tok));
        toks = toks_alloc;

        if (tmp != toks_buf)
          free(tmp);
      }

      if ((max_toks != 0) && ((cur_tok + 1) == (size_t) max_toks)) {
        /* Return rest of string as last tok */
        *num_toks = cur_tok + 1;

        /* Already got a ret string */
        if (toks != toks_alloc) {
          retstr = (char **) calloc(sizeof(char *) * (cur_tok + 1), sizeof(char));
          memcpy(retstr, toks, (sizeof(char *) * (cur_tok + 1)));
        } else {
          retstr = toks;
        }

        /* Trim whitespace at end of last tok */
        for (j = str_length; j > tok_start; j--) {
          if (!isspace((int) str[j - 1]))
            break;
        }

        retstr[cur_tok] = strndup(&str[i], j - i);
        if (retstr[cur_tok] == NULL) {
          mSplitFree(&retstr, cur_tok + 1);
          return NULL;
        }

        return retstr;
      }

      tok_start = i--;
    } else {
      /* This character is escaped with the meta char */
      escaped = 0;
    }
  }

  /* Last character was an escape character */
  if (escaped) {
    for (i = 0; i < cur_tok; i++)
      free(toks[i]);

    if (toks == toks_alloc)
      free(toks_alloc);

    return NULL;
  }

  /* Trim whitespace at end of last tok */
  for (j = i; j > tok_start; j--) {
    if (!isspace((int) str[j - 1]))
      break;
  }

  /* Last character was not a separator character so we've got
   * one more tok.  Unescape escaped sepatator charactors */
  if (toks != toks_alloc) {
    retstr = (char **) calloc(sizeof(char *) * (cur_tok + 1), sizeof(char));
    memcpy(retstr, toks, (sizeof(char *) * (cur_tok + 1)));
  } else {
    retstr = toks;
  }

  retstr[cur_tok] = mSplitAddTok(&str[tok_start], j - tok_start, sep_chars, meta_char);

  /* Just add one to cur_tok index instead of incrementing
   * since we're done */
  *num_toks = cur_tok + 1;
  return retstr;
}