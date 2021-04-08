#include "parser.h"
#include "signature.h"
#include "defs.h"
#include <iostream>
#include "snort-funcs/misc.h"
#include <cstring>
#include <vector>
#include <map>
#include "suricata-funcs.h"

typedef int (*ParseRuleFunc)(Signature *sid, char *);

typedef struct _RuleFunc
{
    char *name;
    ParseRuleFunc parse_func;

} RuleFunc;

static const RuleFunc rule_options[] =
    {
        {RULE_OPT_MSG, ParseRuleMessage},
        {RULE_OPT_CONTENT, ParseRuleContent},
        {RULE_OPT_SID, ParseRuleSid},
        {NULL, NULL} /* Marks end of array */
};

int ParseRuleFlow(Signature *sig, char *args)
{
    if (strcasecmp(args, "<-") == 0)
    {
        sig->flowdir = FLOWDIR_TOCLIENT;
        return 0;
    }
    else if (strcasecmp(args, "->") == 0)
    {
        sig->flowdir = FLOWDIR_TOSERVER;

        return 0;
    }
    return -1;
}

int ParseRuleMessage(Signature *sig, char *args)
{
    // printf("[PARSEMESSAGE][INFO]: message %s\n", args);
    int ovlen = strlen(args);
    if (ovlen > 1)
    {
        /* strip leading " */
        args++;
        ovlen--;
        args[ovlen - 1] = '\0';
        ovlen--;
    }

    sig->msg = strdup(args);
    return 0;
}

int ParseRuleContent(Signature *sig, char *args)
{
    int ovlen = strlen(args);
    /* skip leading whitespace */
    while (ovlen > 0)
    {
        if (!isblank(*args))
            break;
        args++;
        ovlen--;
    }

    /* see if value is negated */
    if (*args == '!')
    {
        args++;
        ovlen--;
    }
    /* skip more whitespace */
    while (ovlen > 0)
    {
        if (!isblank(*args))
            break;
        args++;
        ovlen--;
    }

    if (ovlen > 1)
    {
        /* strip leading " */
        args++;
        ovlen--;
        args[ovlen - 1] = '\0';
        ovlen--;
    }
    if (DetectContentDataParse(args, sig) != 0)
    {
        return -1;
    }
    else
    {
        return 0;
    }
}

int ParseRuleSid(Signature *sig, char *args)
{
    sig->sid = atoi(args);
    return 0;
}

int ParseOptions(Signature *sig, char *rule_opts)
{
    if (rule_opts == NULL)
    {
        printf("No rule options.\n");
    }
    else
    {
        char **toks;
        int num_toks;
        int i;

        if ((rule_opts[0] != '(') || (rule_opts[strlen(rule_opts) - 1] != ')'))
        {
            printf("Rule options must be enclosed in '(' and ')'.");
        }

        /* Move past '(' and zero out ')' */
        rule_opts++;
        rule_opts[strlen(rule_opts) - 1] = '\0';
        toks = mSplit(rule_opts, ";", 0, &num_toks, '\\');

        for (i = 0; i < num_toks; i++)
        {
            char **opts;
            int num_opts;
            char *option_args = NULL;
            int j;

            //printf("option: %s\n", toks[i]);

            /* break out the option name from its data */
            opts = mSplit(toks[i], ":", 2, &num_opts, '\\');

            //printf("   option name: %s\n", opts[0]);

            if (num_opts == 2)
            {
                option_args = opts[1];
                //   printf("   option args: %s\n", option_args);
            }

            for (j = 0; rule_options[j].name != NULL; j++)
            {
                if (strcasecmp(opts[0], rule_options[j].name) == 0)
                {
                    if (rule_options[j].parse_func(sig, option_args) != 0)
                    {
                        mSplitFree(&opts, num_opts);
                        mSplitFree(&toks, num_toks);
                        return -1;
                    }
                }
            }
            mSplitFree(&opts, num_opts);
        }
        mSplitFree(&toks, num_toks);
    }
    return 0;
}

int ParseHeader(Signature *sig, char **toks)
{
    /* Set the rule protocol - fatal errors if protocol not found */
    uint8_t protocol = GetRuleProtocol(toks[1]);
    switch (protocol)
    {
    case IPPROTO_TCP:
        sig->protocol = IPPROTO_TCP;
        break;
    case IPPROTO_UDP:
        sig->protocol = IPPROTO_UDP;
        break;
    case ERROR_RETURN:
        return -1;
    }

    if (ParseRuleFlow(sig, toks[4]) != 0)
    {
        return -1;
    }

    if (sig->flowdir == FLOWDIR_TOCLIENT)
    {
        if (ParsePorts(sig, toks[3] /* =src port */) != 0)
        {
            return -1;
        }
    }
    else
    {
        if (ParsePorts(sig, toks[6] /* =dst port */) != 0)
        {
            return -1;
        }
    }

    return 0;
}

int ParseSigFile(std::vector<Signature *> &sig_list, const char *sig_file)
{
    int signum = 0;
    char line[8192];
    long offset = 0;
    int lineno = 0;
    int multiline = 0;

    FILE *fp = fopen(sig_file, "r");
    if (fp == nullptr)
    {
        printf("[PARSE][ERROR]: opening rule file %s", sig_file);
        return -1;
    }

    while (fgets(line + offset, (int)sizeof(line) - offset, fp) != nullptr)
    {
        lineno++;
        int len = strlen(line);

        /* ignore comments and empty lines */
        if (line[0] == '\n' || line[0] == '\r' || line[0] == ' ' || line[0] == '#' || line[0] == '\t')
            continue;

        /* Check for multiline rules. */
        while (len > 0 && isspace((unsigned char)line[--len]))
            ;
        if (line[len] == '\\')
        {
            multiline++;
            offset = len;
            if (offset < sizeof(line) - 1)
            {
                /* We have room for more. */
                continue;
            }
            /* No more room in line buffer, continue, rule will fail
             * to parse. */
        }

        /* Check if we have a trailing newline, and remove it */
        len = strlen(line);
        if (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
        {
            line[len - 1] = '\0';
        }

        /* Reset offset. */
        offset = 0;

        /* Parse the signature */
        Signature *sig = new Signature();
        if (AppendSignature(sig, line, signum) == 0 && (sig->content && sig->dstport.size() && sig->flowdir))
        {
            sig_list.push_back(sig);
            signum++;
        }
        else
        {
            if (sig->content)
                free(sig->content);
            if (sig->msg)
                free(sig->msg);
            delete (sig); // use delete, because of "new"
        }

        multiline = 0;
    }
    fclose(fp);
    return signum;
}

int AppendSignature(Signature *sig, char *line, int signum)
{
    char **toks = NULL;
    int num_toks = 0;
    // Signature *sig = new Signature();
    sig->id = signum;

    toks = mSplit(line, " \t", 8, &num_toks, '\\');
    char *roptions = toks[7];
    if (ParseOptions(sig, roptions) != 0)
    {
        mSplitFree(&toks, num_toks);
        return -1;
    }
    if (ParseHeader(sig, toks) != 0)
    {
        mSplitFree(&toks, num_toks);
        return -1;
    }
    mSplitFree(&toks, num_toks);
    return 0;
}

int GetRuleProtocol(char *proto_str)
{
    if (strcasecmp(proto_str, RULE_PROTO_OPT_TCP) == 0)
    {
        return IPPROTO_TCP;
    }
    else if (strcasecmp(proto_str, RULE_PROTO_OPT_UDP) == 0)
    {
        return IPPROTO_UDP;
    }
    else
    {
        return -1;
    }
}

int ParsePorts(Signature *sig, char *port_str)
{

    /* 1st - check if we have an any port */
    if (strcasecmp(port_str, "any") == 0)
    {
        sig->dstport = {ANYPORT};
        return 0;
    }

    /* 2nd - check if we have a PortVar */
    else if (port_str[0] == '$')
    {
        auto ports = port_vartable.find(port_str);
        if (ports != port_vartable.end())
        { // found key
            sig->dstport = ports->second;
            return 0;
        }
        return -1;

    } /* 3rd -  and finally process a raw port list */
    else
    {
        if (port_str[0] == '[')
        {
            int ovlen = strlen(port_str);

            if (ovlen > 1)
            {
                /* strip leading " */
                port_str++;
                ovlen--;
                port_str[ovlen - 1] = '\0';
                ovlen--;
            }
        }
        std::vector<uint32_t> tmpar;
        int num_toks;
        char **toks = mSplit(port_str, ",", 0, &num_toks, '\\');

        for (size_t i = 0; i < num_toks; i++)
        {
            int tmp_ret = atoi(toks[i]);
            if (tmp_ret == 0)
            {
                mSplitFree(&toks, num_toks);
                return -1;
            }
            tmpar.push_back(tmp_ret);
        }
        if (tmpar.size())
        {
            sig->dstport = tmpar;
        }
        mSplitFree(&toks, num_toks);
        return 0;
    }
}
