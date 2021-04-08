#ifndef SURICATA_FUNCS_H
#define SURICATA_FUNCS_H
#include <iostream>
#include "signature.h"
// Taken from detect-content.c
int DetectContentDataParse(const char *contentstr, Signature *sig);
#endif