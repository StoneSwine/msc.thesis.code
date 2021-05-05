#ifndef NTREE_H
#define NTREE_H

#include "signature.h"
#include "defs.h"


typedef struct Portnode_ {
  Portnode_ *next = nullptr;
  Signature *sn;
} Portnode;

typedef struct Flownode_ {
  Portnode *tcp[MAX_PORTS];
  Portnode *udp[MAX_PORTS];
} Flownode;

typedef struct Rootnode_ {
  Flownode *flow_gh[MAXFLOW];
} Rootnode;

#endif
