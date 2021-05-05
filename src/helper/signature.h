#ifndef SIGNATURE_H
#define SIGNATURE_H

#include "defs.h"
#include <iostream>
#include <vector>

typedef struct Signature_ {
  uint8_t protocol;
  std::vector<uint32_t> dstport;

  int id;
  char *msg;
  uint16_t clen = 0;
  uint8_t *content;
  int sid;
  int flowdir;
} Signature;

#endif
