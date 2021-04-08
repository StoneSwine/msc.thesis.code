

#include <iostream>
#include <sdsl/bit_vectors.hpp>
#include <sdsl/wavelet_trees.hpp>
#include <string>
#include "snort-funcs/acsmx.h"
#include "parser.h"
#include "signature.h"
#include <mapper.hpp>
#include <cstdlib>
#include <elias_fano_compressed_list.hpp>

using namespace sdsl;
using namespace std::chrono;
using timer = std::chrono::high_resolution_clock;

ACSM_STRUCT *acsm = acsmNew();

int main(int argc, char *argv[])
{

    char *infile, *outfile, *searchtext;
    searchtext = nullptr;
    int no_samples = 1;
    int wtf = 0;
    unsigned char *text;
    if (argc < 8)
    {
        fprintf(stderr, "Usage: ./program -o outfile -i infile -s sampleno -st searchtext (-w)\n");
        exit(0);
    }

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-o") == 0)
        {
            outfile = argv[i + 1];
        }
        else if (strcmp(argv[i], "-i") == 0)
        {
            infile = argv[i + 1];
        }
        else if (strcmp(argv[i], "-s") == 0)
        {
            no_samples = atoi(argv[i + 1]);
        }
        else if (strcmp(argv[i], "-w") == 0)
        {
            wtf = 1;
        }
        else if (strcmp(argv[i], "-st") == 0)
        {
            searchtext = argv[i + 1];
        }
    }

    std::vector<Signature *> sig_list;
    ParseSigFile(sig_list, infile);
    std::ifstream input(searchtext, std::ios::in | std::ios::binary);
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(input)), (std::istreambuf_iterator<char>()));
    input.close();

    uint64_t lg_bt, ac_bt = 0;

    auto start = timer::now();

    for (size_t i = 0; i < sig_list.size(); i++)
    {
        acsmAddPattern(acsm, sig_list[i]->content, sig_list[i]->clen, 0, i);
    }

    acsmCompile(acsm);

    uint l;
    uint r;
    std::vector<uint> lg_l_total, ac_l_total, lg_s_total, ac_s_total;

    std::ofstream of_st;

    std::vector<uint> tmp_n; // temporary

    auto stop = timer::now();
    ac_bt = duration_cast<TIMEUNIT>(stop - start).count();
    int m = 0;
    float lgtm;
    int ac_nfound;

    if (acsm->acsmMaxStates <= 1 || acsm->numPatterns <= 50)
    {
        exit(0);
    }
    float notzerosates;
    for (size_t i = 0; i < no_samples; i++)
    {

        notzerosates = 0.0f;

        // Aho-corasick search
        start = timer::now();
        ac_nfound = acsmSearch(acsm, reinterpret_cast<unsigned char *>(bytes.data()), bytes.size(), (void *)0, 0);
        stop = timer::now();
        int ac_st = duration_cast<TIMEUNIT>(stop - start).count();

        int next;
        uint c = 0;
        uint state = 0;
        bit_vector nb(ALPHABET_SIZE * acsm->acsmMaxStates + 1);
        auto start = timer::now();

        for (int k = 0; k < ALPHABET_SIZE; k++)
        {
            for (int i = 0; i < acsm->acsmMaxStates; i++)
            {
                next = acsm->acsmStateTable[i].NextState[k];
                if (next > 0)
                {
                    notzerosates++;
                    tmp_n.push_back(next);
                    nb[c] = 1;
                }
                if (next >= 0)
                {
                    c++;
                }
                
            }
        }

        nb.resize(c);

        succinct::elias_fano_compressed_list N(tmp_n);

        tmp_n.clear();
        tmp_n.shrink_to_fit();
        int lg_nfound = 0;
        auto stop = timer::now();
        lg_bt = duration_cast<TIMEUNIT>(stop - start).count();

        uint s = (acsm->acsmNumStates + 1);

        rank_support_v<1> nb_r1(&nb);

        start = timer::now();
        for (auto i : bytes)
        {
            r = i * s;
            if (nb[r + state])
            {
                state = N[nb_r1(r + state)];
                if (acsm->acsmStateTable[state].MatchList != NULL)
                {
                    printf("[LG]:Match for %s\n", acsm->acsmStateTable[state].MatchList->casepatrn);
                    lg_nfound++;
                }
            }
            else
            {
                state = 0;
            }
        }

        stop = timer::now();
        assert(lg_nfound == ac_nfound); // Assert that the two versions match equally as many patterns.
        int lg_st = duration_cast<TIMEUNIT>(stop - start).count();
        lgtm = (float)succinct::mapper::size_tree_of(N)->size + (float)size_in_bytes(nb);

        if (!wtf)
        {
            printf("\n+--[Summary]-------------------------------------------------\n");
            printf("| Filename                      : %s\n", infile);
            printf("| Percent zero states           : %0.2f%\n", ((c-notzerosates) / c) * 100.0f);
            printf("| No. Signatures                : %lu \n", sig_list.size());
            printf("| Number of Matches             : %ld\n", ac_nfound);
            printf("+--[Pattern Matcher:Labeled graph Summary]----------------------\n");
            printf("| N                             : %lu B\n", succinct::mapper::size_tree_of(N)->size);
            printf("| B                             : %lu B\n", size_in_bytes(nb));

            if (lgtm < 1024 * 1024)
                printf("| Total                         : %.5f KB\n", lgtm / 1024.0f);
            else
                printf("| Total                         : %.5f MB\n", lgtm / (1024.0f * 1024.0f));
            printf("| Search time (ns)              : %d\n", lg_st);
            printf("| Build time (ns)               : %ld\n", lg_bt);
            printf("+--[Pattern Matcher:Aho-Corasick Summary]----------------------\n");
            acsmPrintSummaryInfo(acsm);
            printf("| Search time (ns)              : %ld\n", ac_st);
            printf("| Build time (ns)               : %ld\n", ac_bt);
            printf("+--------------------------------------------------------------\n");
        }
        else
        {
            ac_l_total.push_back(ac_st);
            ac_s_total.push_back(getMem(acsm));
            lg_l_total.push_back(lg_st);
            lg_s_total.push_back(lgtm);
        }
    }

    if (wtf)
    {
        float timedif = ((float)(std::accumulate(lg_l_total.begin(), lg_l_total.end(), 0)) / (no_samples)) / ((float)(std::accumulate(ac_l_total.begin(), ac_l_total.end(), 0)) / (no_samples));
        float sizedif = ((float)getMem(acsm) / (float)lgtm);

        of_st.open(outfile);
        of_st << "No. matches: "
              << ac_nfound
              << "; time differenes: "
              << timedif
              << " size differences: "
              << sizedif
              << " ratio: "
              << timedif / sizedif
              << "\n";
        of_st << "sample, ac_time, lg_time, ac_space, lg_space, num_states, num_patterns\n";
        for (size_t i = 0; i < no_samples; i++)
        {
            of_st << (i + 1) << "," << ac_l_total[i] << "," << lg_l_total[i] << "," << ac_s_total[i] << "," << lg_s_total[i] << "," << acsm->acsmMaxStates << "," << acsm->numPatterns << std::endl;
        }
        of_st.close();
    }

    acsmFree(acsm);

    return 0;
}
