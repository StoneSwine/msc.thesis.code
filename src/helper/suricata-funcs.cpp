#include <iostream>
#include <string.h>
#include "signature.h"

/**
  *  \brief Parse a content string, ie "abc|DE|fgh"
  *
  *  \param contentstr null terminated string containing the content
  *  \param pstr result pointer to pass the fully parsed byte array
  *  \param plen size of the resulted data
  *
  *  \retval -1 error
  *  \retval 0 ok
  */
int DetectContentDataParse(const char *contentstr, Signature *sig) {
  char *str = NULL;
  size_t slen = 0;

  slen = strlen(contentstr);
  if (slen == 0) {
    return -1;
  }
  uint8_t buffer[slen + 1];
  strncpy((char *) &buffer, contentstr, slen + 1);
  str = (char *) buffer;

  char converted = 0;
  uint16_t i, x;
  uint8_t bin = 0;
  uint8_t escape = 0;
  uint8_t binstr[3] = "";
  uint8_t binpos = 0;
  uint16_t bin_count = 0;

  for (i = 0, x = 0; i < slen; i++) {
    if (str[i] == '|') {
      bin_count++;
      if (bin) {
        bin = 0;
      } else {
        bin = 1;
      }
    } else if (!escape && str[i] == '\\') {
      escape = 1;
    } else {
      if (bin) {
        if (isdigit((unsigned char) str[i]) ||
            str[i] == 'A' || str[i] == 'a' ||
            str[i] == 'B' || str[i] == 'b' ||
            str[i] == 'C' || str[i] == 'c' ||
            str[i] == 'D' || str[i] == 'd' ||
            str[i] == 'E' || str[i] == 'e' ||
            str[i] == 'F' || str[i] == 'f') {

          binstr[binpos] = (char) str[i];
          binpos++;

          if (binpos == 2) {
            uint8_t c = strtol((char *) binstr, (char **) NULL, 16) & 0xFF;
            binpos = 0;
            str[x] = c;
            x++;
            converted = 1;
          }
            //  } else if (str[i] == ' ') {
            //      // SCLogDebug("space as part of binary string");
            //  }
          else if (str[i] != ',') {
            //  SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid hex code in "
            //              "content - %s, hex %c. Invalidating signature.", str, str[i]);
            return -1;
          }
        } else if (escape) {
          if (str[i] == ':' ||
              str[i] == ';' ||
              str[i] == '\\' ||
              str[i] == '\"') {
            str[x] = str[i];
            x++;
          } else {
            //  SCLogError(SC_ERR_INVALID_SIGNATURE, "'%c' has to be escaped", str[i-1]);
            return -1;
          }
          escape = 0;
          converted = 1;
        } else if (str[i] == '"') {
          //  SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid unescaped double quote within content section.");
          return -1;
        } else {
          str[x] = str[i];
          x++;
        }
      }
    }

    if (bin_count % 2 != 0) {
      //  SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid hex code assembly in "
      // "%s - %s.  Invalidating signature.", keyword, contentstr);
      return -1;
    }

    if (converted) {
      slen = x;
    }
  }

  if (slen) {
    if (slen > sig->clen) {
      sig->content = (uint8_t *) calloc(slen, sizeof(uint8_t));
      if (sig->content == NULL) {
        return -1;
      }
      memcpy(sig->content, str, slen);
      sig->clen = (uint16_t) slen;
      return 0;
    }
  }

  return -1;
}