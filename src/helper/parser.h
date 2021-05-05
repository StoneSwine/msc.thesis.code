#ifndef PARSER_H
#define PARSER_H

#include "defs.h"
#include "signature.h"
#include <vector>
#include <map>

// Some predefined port variables..
inline std::map<std::string, std::vector<uint32_t>> port_vartable = {
    {"$HTTP_PORTS",      {80,  81, 311, 383, 591, 593, 901, 1220, 1414, 1741, 1830, 2301, 2381, 2809, 3037, 3128, 3702, 4343, 4848, 5250, 6988, 7000, 7001, 7144, 7145, 7510, 7777, 7779, 8000, 8008, 8014, 8028, 8080, 8085, 8088, 8090, 8118, 8123, 8180, 8181, 8243, 8280, 8300, 8800, 8888, 8899, 9000, 9060, 9080, 9090, 9091, 9443, 9999, 11371, 34443, 34444, 41080, 50002, 55555}},
    {"$FILE_DATA_PORTS", {110, 143}},
    {"$FTP_PORTS",       {{21, 2100, 3535}}}};

int ParseRuleMessage(Signature *sid, char *args);

int ParseRuleContent(Signature *sid, char *args);

int ParseRuleSid(Signature *sid, char *args);

int ParseOptions(Signature *sig, char *rule_opts);

int ParseHeader(Signature *sig, char **toks);

int ParseSigFile(std::vector<Signature *> &sig_list, const char *sig_file);

int ParseRuleFlow(Signature *sig, char *args);

int AppendSignature(Signature *sig, char *line, int signum);

int GetRuleProtocol(char *proto_str);

int ParsePorts(Signature *sig, char *port_str);

#endif