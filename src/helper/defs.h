#ifndef DEFS_H
#define DEFS_H

#define RULE_OPT_MSG "msg"
#define RULE_OPT_CONTENT "content"
#define RULE_OPT_SID "sid"
#define RULE_OPT_FLOW "flow"
#define RULE_PROTO_OPT_TCP "tcp"
#define RULE_PROTO_OPT_UDP "udp"
#define TOKS_BUF_SIZE 100
#define FLOWDIR_TOCLIENT 2
#define FLOWDIR_TOSERVER 1
#define MAXFLOW 3
#define MAX_PORTS 65536
#define ERROR_RETURN -1

#define ANYPORT 0

/* Standard well-defined IP protocols.  */
#define IPPROTO_TCP 1
#define IPPROTO_UDP 2
#define IPPROTO_MAX 3

#define VLC_CODER coder::fibonacci
#define TIMEUNIT nanoseconds

#endif