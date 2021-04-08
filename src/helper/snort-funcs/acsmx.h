/* $Id$ */
/*
** Copyright (C) 2014-2020 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Copyright (C) 2002 Martin Roesch <roesch@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

/*
**   ACSMX.H
**
**
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef ACSMX_H
#define ACSMX_H

/*
*   Prototypes
*/

#define ALPHABET_SIZE 256

#define ACSM_FAIL_STATE -1

//inline static unsigned char Tc[64 * 1024];

typedef struct _acsm_pattern
{

    struct _acsm_pattern *next;
    unsigned char *patrn;
    unsigned char *casepatrn;
    int n;
    int nocase;
    int offset;
    int depth;
    int iid;

} ACSM_PATTERN;

typedef struct
{

    /* Next state - based on input character */
    uint NextState[ALPHABET_SIZE];

    /* Failure state - used while building NFA & DFA  */
    int FailState;

    /* List of patterns that end here, if any */
    ACSM_PATTERN *MatchList;

} ACSM_STATETABLE;

/*
* State machine Struct
*/
typedef struct
{

    int acsmMaxStates;
    int acsmNumStates;

    ACSM_PATTERN *acsmPatterns;
    ACSM_STATETABLE *acsmStateTable;

    int bcSize;
    short bcShift[256];

    int numPatterns;

    int alphabetsize;

} ACSM_STRUCT;

/*
*   Prototypes
*/
ACSM_STRUCT *acsmNew();

int acsmAddPattern(ACSM_STRUCT *p, unsigned char *pat, int n,
                   int nocase,
                   int iid);

int acsmCompile(ACSM_STRUCT *acsm);

int acsmSearch(ACSM_STRUCT *acsm, unsigned char *T, int n,
               void *data, int *current_state);

void acsmFree(ACSM_STRUCT *acsm);
int acsmPatternCount(ACSM_STRUCT *acsm);
int getMem(ACSM_STRUCT *acsm);
int acsmPrintSummaryInfo(ACSM_STRUCT *acsm);

#endif
