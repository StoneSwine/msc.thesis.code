/*
 * Author: Magnus Lien Lilja
 * Proof of concept (PoC) comparison of the Aho-Corasick deterministic finite automaton (DFA) algorithm, which is in
 * Snort and Suricata, and the suggested improvement.
 * The program takes a signature file as input, together with a search text and outputs the efficiency, according to a
 * criteria defined in my master thesis.
 */

#include <iostream>
#include <sdsl/bit_vectors.hpp>
#include <sdsl/wavelet_trees.hpp>
#include <string>
#include <mapper.hpp>
#include <cstdlib>
#include <elias_fano_compressed_list.hpp>
#include "snort-funcs/acsmx.h"
#include "parser.h"
#include "signature.h"

using namespace sdsl;
using namespace std::chrono;
using timer = std::chrono::high_resolution_clock;

ACSM_STRUCT *acsm = acsmNew();

int main(int argc, char *argv[]) {

  char *infile, *searchtext;
  searchtext = nullptr;
  int no_samples = 1;

  float c_states = 0.0f;
  int alt_n_siz = 0;
  int alt_b_siz = 0;

  // Parse arguments
  if (argc < 5) {
    fprintf(stderr, "Usage: ./program -i infile -s sampleno -st searchtext\n");
    exit(0);
  }

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-i") == 0) {
      infile = argv[i + 1];
    } else if (strcmp(argv[i], "-s") == 0) {
      no_samples = atoi(argv[i + 1]);
    } else if (strcmp(argv[i], "-st") == 0) {
      searchtext = argv[i + 1];
    }
  }

  // Parse signatures from the input file
  std::vector<Signature *> sig_list;
  ParseSigFile(sig_list, infile);

  // Read search text as bytes
  std::ifstream input(searchtext, std::ios::in | std::ios::binary);
  std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(input)), (std::istreambuf_iterator<char>()));
  input.close();

  // Use the existing functionality from Snort to add patterns and compile the DFA
  for (size_t i = 0; i < sig_list.size(); i++) {
    acsmAddPattern(acsm, sig_list[i]->content, sig_list[i]->clen, 0, i);
  }
  acsmCompile(acsm);

  uint r;
  std::vector<uint> lg_l_total, ac_l_total;
  std::vector<uint> tmp_n; // temporary
  float lgtm;
  int ac_nfound;
  float notzerosates;

  // Exit if few patterns or states
  if (acsm->acsmMaxStates <= 1 || acsm->numPatterns <= 50) {
    exit(0);
  }


  for (size_t i = 0; i < no_samples; i++) {
    notzerosates = 0.0f;
    // Aho-corasick search and time it
    auto start = timer::now();
    ac_nfound = acsmSearch(acsm, reinterpret_cast<unsigned char *>(bytes.data()), bytes.size(), (void *) 0, 0);
    auto stop = timer::now();
    int ac_st = duration_cast<TIMEUNIT>(stop - start).count();

    // Build the alternative representation
    int next;
    uint c = 0;
    uint state = 0;
    bit_vector nb(ALPHABET_SIZE * acsm->acsmMaxStates + 1);

    for (int k = 0; k < ALPHABET_SIZE; k++) {
      for (int i = 0; i < acsm->acsmMaxStates; i++) {
        next = acsm->acsmStateTable[i].NextState[k];
        if (next > 0) {
          notzerosates++;
          tmp_n.push_back(next);
          nb[c] = 1;
        }
        if (next >= 0) {
          c++;
        }

      }
    }

    nb.resize(c);
    succinct::elias_fano_compressed_list N(tmp_n);

    tmp_n.clear();
    tmp_n.shrink_to_fit();
    int lg_nfound = 0;

    uint s = (acsm->acsmNumStates + 1);
    rank_support_v<1> nb_r1(&nb);

    // Use the developed algorithm to search for matches in the improved representation.
    // The existing matchList from Aho-Corasick in Snort is used here, but not accounted for memory-wise in either of
    // the two algorithms
    start = timer::now();
    for (auto i : bytes) {
      r = i * s;
      if (nb[r + state]) {
        state = N[nb_r1(r + state)];
        if (acsm->acsmStateTable[state].MatchList != NULL) {
          printf("[LG]:Match for %s\n", acsm->acsmStateTable[state].MatchList->casepatrn);
          lg_nfound++;
        }
      } else {
        state = 0;
      }
    }

    stop = timer::now();

    // Assert that the two versions match equally as many patterns.
    assert(lg_nfound == ac_nfound);

    // Register time and space
    int lg_st = duration_cast<TIMEUNIT>(stop - start).count();
    lgtm = (float) succinct::mapper::size_tree_of(N)->size + (float) size_in_bytes(nb);

    alt_b_siz = size_in_bytes(nb);
    alt_n_siz = succinct::mapper::size_tree_of(N)->size;

    ac_l_total.push_back(ac_st);
    lg_l_total.push_back(lg_st);
    c_states = c;
  }

  // Calculate median: https://en.cppreference.com/w/cpp/algorithm/nth_element
  const auto Xi_m = (lg_l_total.begin() + lg_l_total.size() / 2);
  const auto Xe_m = (ac_l_total.begin() + ac_l_total.size() / 2);

  std::nth_element(lg_l_total.begin(), Xi_m, lg_l_total.end());
  std::nth_element(ac_l_total.begin(), Xe_m, ac_l_total.end());

  // Original space and time
  auto We = (float) getMem(acsm);
  auto Xe = (float) *Xe_m;
  // Alternative space and time
  auto Wi = (float) lgtm;
  auto Xi = (float) *Xi_m;

  printf("\n+--[Summary]-------------------------------------------------\n");
  printf("| Samples:                              : %d\n", no_samples);
  printf("| Filename                              : %s\n", infile);
  printf("| Percent zero states                   : %.2f%%\n", ((c_states - notzerosates) / c_states) * 100.0f);
  printf("| No. Signatures                        : %lu \n", sig_list.size());
  printf("| Number of Matches                     : %d\n", ac_nfound);
  printf("+--[ORIGINAL representation]----------------------\n");
  acsmPrintSummaryInfo(acsm);
  printf("| Size (We)                             : %.1f B\n", We);
  printf("| Median search time in ns (Xe)         : %.1f\n", Xe);
  printf("+--[ALTERNATIVE representation]----------------------\n");
  printf("| N                                     : %d B\n", alt_n_siz);
  printf("| B                                     : %d B\n", alt_b_siz);
  if (lgtm < 1024 * 1024)
    printf("| Size (Wi)                             : %.5f KB\n", Wi / 1024.0f);
  else
    printf("| Size (Wi)                             : %.5f MB\n", Wi / (1024.0f * 1024.0f));
  printf("| Size (Wi)                             : %.1f B\n", Wi);
  printf("| Median search time in ns (Xi)         : %.1f\n", Xi);
  printf("+-[EFFICIENCY]-----------------------------------------------------\n");
  printf("| Space difference (We / Wi)            : %.5f\n", (We / Wi));
  printf("| Time difference  (Xi / Xe)            : %.5f\n", (Xi / Xe));
  printf("| Result     (We * Xe) / (Wi * Xi)      : %.5f\n", (We * Xe) / (Wi * Xi));
  printf("+------------------------------------------------------------------\n");


  acsmFree(acsm);

  for (auto sig : sig_list) {
    free(sig->content);
    free(sig->msg);

    delete (sig); // use delete, because of "new"
  }

  return 0;
}
