/*
 * Author: Magnus Lien Lilja
 *
 */

#include <cstdio>
#include <ctime>

#include <elias_fano_compressed_list.hpp>
#include <mapper.hpp>

#include "parser.h"
#include "ptree.h"
#include "ltree.h"
#include "signature.h"
#include <ostream>
#include "defs.h"

using namespace sdsl;
using namespace std;
using namespace std::chrono;
using timer = std::chrono::high_resolution_clock;

int main(int argc, char *argv[]) {
  int no_samples = 2;
  vector<uint> l_total;
  vector<uint> l_select_unique;
  vector<uint> p_total;
  char *infile;

  int unique_ports = 0;
  int signo_sb_orig = 0;
  int signo_sb_alt = 0;
  int alt_b_siz = 0;
  int alt_s_siz = 0;


  if (argc < 3) {
    fprintf(stderr, "Usage: ./program -i infile -s sampleno\n");
    exit(0);
  }
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-i") == 0) {
      infile = argv[i + 1];
    } else if (strcmp(argv[i], "-s") == 0) {
      no_samples = atoi(argv[i + 1]);
    }
  }

  uint64_t p_node_size_b, sig_size_b, l_vlcp_size_b, l_vlcc_size_b, p_ct_ms, l_ct_ms;

  std::vector<Signature *> sig_list;
  ParseSigFile(sig_list, infile);
  //               size of the pointers               +  the size of the objects in the list
  sig_size_b += sizeof(Signature *) * sig_list.size() + (sizeof(Signature) * sig_list.size());
  sig_size_b += sizeof(sig_list);

  if (sig_list.size() <= 50) {
    exit(0);
  }

  for (size_t x = 0; x < no_samples; x++) {

    /* Size variables in bytes (b).
   * The sizes of the relations between the nodes are what's stored, and not the nodes themselves (new...)
  */
    p_node_size_b = l_vlcp_size_b = l_vlcc_size_b = p_ct_ms = l_ct_ms = 0;

    // Initialise tree

    Rootnode *root = new Rootnode();
    p_node_size_b += sizeof(Rootnode *);
    p_node_size_b += sizeof(Rootnode);
    Flownode **cn_f;
    Portnode **cn_p, *cn_p_tmp;

    for (size_t i = 0; i < MAXFLOW; i++) {
      root->flow_gh[i] = new Flownode();
      p_node_size_b += sizeof(Flownode);
      for (size_t j = 0; j < MAX_PORTS; j++) {
        root->flow_gh[i]->tcp[j] = nullptr;
        root->flow_gh[i]->udp[j] = nullptr;
      }
    }

    for (Signature *sig : sig_list) {
      if (sig->flowdir == FLOWDIR_TOCLIENT) {
        cn_f = &root->flow_gh[FLOWDIR_TOCLIENT];
      } else // TOSERVER
      {
        cn_f = &root->flow_gh[FLOWDIR_TOSERVER];
      }

      for (auto sp : sig->dstport) {
        if (sig->protocol == IPPROTO_TCP) {
          cn_p = &(*cn_f)->tcp[sp];
        } else {
          cn_p = &(*cn_f)->udp[sp];
        }

        Portnode *temp_pn = new Portnode();
        temp_pn->sn = sig;

        // list is empty
        if (!(*cn_p)) {
          (*cn_p) = temp_pn;
          p_node_size_b += sizeof(Portnode);
        } else { // traverse list until last node is reached and insert

          Portnode *last = (*cn_p);

          while (last->next) {
            last = last->next;
          }

          last->next = temp_pn;
          p_node_size_b += sizeof(Portnode);
        }
      }
    }

    /*
 * Build the structure 
 */
    std::set<uint32_t> up;
    for (auto sig : sig_list) {
      for (auto sp : sig->dstport) {
        up.insert(sp);
      }
    }
    std::vector<uint32_t> up_it(up.begin(), up.end());

    if (up_it.size() <= 1) {
      exit(0);
    }

    ltree<bit_vector, select_support_mcl<1>, select_support_mcl<0>, rank_support_v5<1>, rank_support_v<0>> l;
    // Build the "static" tree level order
    l.append(2, {FLOWDIR_TOSERVER, FLOWDIR_TOCLIENT});
    for (size_t i = 0; i < MAXFLOW; i++) {
      l.append(2, {IPPROTO_TCP, IPPROTO_UDP});
    }
    for (size_t i = 0; i < MAXFLOW * IPPROTO_MAX; i++) {
      l.append(up_it.size(), up_it);
    }
    for (size_t i = 0; i < MAXFLOW + IPPROTO_MAX; i++) {
      for (auto p : up) {
        l.append(0);
      }
    }
    l.finalize();

    /*
 * Insert the signature ids 
 */
    int sc = 8; // number of nodes in the "skeleton

    const int no_protport = (MAXFLOW + IPPROTO_MAX) * up_it.size();
    std::vector<uintptr_t> tmp_vlc[no_protport];

    for (auto sig : sig_list) {
      int nodeid = 1;
      if (sig->flowdir == FLOWDIR_TOCLIENT) {
        nodeid = l.labeledchild(nodeid, FLOWDIR_TOCLIENT);
      } else {
        nodeid = l.labeledchild(nodeid, FLOWDIR_TOSERVER);
      }

      // Depth 2
      if (sig->protocol == IPPROTO_TCP) {
        nodeid = l.labeledchild(nodeid, IPPROTO_TCP);
      } else {
        nodeid = l.labeledchild(nodeid, IPPROTO_UDP);
      }

      // Depth 3
      int pnid = nodeid;
      for (auto sp : sig->dstport) {
        nodeid = l.labeledchild(pnid, sp) - sc;
        if (nodeid >= 0) {
          tmp_vlc[nodeid].push_back(reinterpret_cast<std::uintptr_t>(sig));
        }
      }
    }

    /*
  * Build the vlc codes and clear the temporary vector
  */
    std::vector<uintptr_t> tmp;
    bit_vector vlc_bv(0, 0);

    int maxpos_count = 0;
    int sigid = 0;

    for (size_t i = 0; i < no_protport; i++) {
      int noc = tmp_vlc[i].size();
      if (noc > maxpos_count) {
        maxpos_count = noc;
        sigid = ((Signature *) tmp_vlc[i].back())->id;
      }
      bit_vector tmp_bv = vlc_bv;
      tmp_bv.resize(vlc_bv.size() + noc + 1);
      int pos = vlc_bv.size();
      tmp_bv[pos++] = 1;

      for (size_t j = 0; j < noc; j++) {
        tmp_bv[pos++] = 0;
        tmp.push_back(tmp_vlc[i][j]);
      }

      tmp_bv.resize(pos);
      vlc_bv = bit_vector(std::move(tmp_bv));

      tmp_vlc[i].clear();
      tmp_vlc[i].shrink_to_fit();
    }

    succinct::elias_fano_compressed_list vlcarray(tmp);

    tmp.clear();
    tmp.shrink_to_fit();

    select_support_mcl<1> vlc_bv_s1(&vlc_bv);
    rank_support_v<0> vlc_bv_r0(&vlc_bv);

    l_vlcc_size_b += (float) succinct::mapper::size_tree_of(vlcarray)->size;
    l_vlcp_size_b += size_in_bytes(vlc_bv);

    // Search for all matching (a random signature id?), and see if the result is same...?
    // Have a nodeid, and want to get all the matching signature ID's

    // Search for signature in a LOUDS based representation

    Signature *findme = sig_list[sigid];
    auto start = timer::now();

    int nodeid = 1;
    if (findme->flowdir == FLOWDIR_TOCLIENT) {
      nodeid = l.labeledchild(nodeid, FLOWDIR_TOCLIENT);
    } else {
      nodeid = l.labeledchild(nodeid, FLOWDIR_TOSERVER);
    }

    // Depth 2
    if (findme->protocol == IPPROTO_TCP) {
      nodeid = l.labeledchild(nodeid, IPPROTO_TCP);
    } else {
      nodeid = l.labeledchild(nodeid, IPPROTO_UDP);
    }

    // Depth 3
    int pnid = nodeid;
    int lfound, pfound;
    lfound = 0;
    pfound = 1;
    nodeid = l.labeledchild(pnid, findme->dstport[0]) - sc;
    if (nodeid >= 0) {

      int i = vlc_bv_r0(vlc_bv_s1(nodeid + 1));
      int stop = vlc_bv_r0(vlc_bv_s1(nodeid + 2));

      for (i; i < stop; i++) {
        lfound++;
        if (((Signature *) vlcarray[i]) == findme) {
          printf("[LOUDS]:FOUND THE SIGNATURE!\n");
        }
      }
    }

    // Search for signature in pointer based representation
    auto stop = timer::now();
    l_ct_ms = duration_cast<TIMEUNIT>(stop - start).count();

    start = timer::now();
    if (findme->flowdir == FLOWDIR_TOCLIENT) {
      cn_f = &root->flow_gh[FLOWDIR_TOCLIENT];
    } else // TOSERVER
    {
      cn_f = &root->flow_gh[FLOWDIR_TOSERVER];
    }

    if (findme->protocol == IPPROTO_TCP) {
      cn_p = &(*cn_f)->tcp[findme->dstport[0]];
    } else {
      cn_p = &(*cn_f)->udp[findme->dstport[0]];
    }

    while ((*cn_p)->next != nullptr) {
      pfound++;
      *cn_p = (*cn_p)->next;
      if ((*cn_p)->sn == findme) {
        printf("[POINTER]:FOUND THE SIGNATURE!\n");
      }
    }
    assert(pfound == lfound);
    stop = timer::now();
    p_ct_ms = duration_cast<TIMEUNIT>(stop - start).count();

    unique_ports = up_it.size();
    signo_sb_alt = lfound;
    signo_sb_orig = pfound;
    alt_b_siz = size_in_bytes(l.bv);
    alt_s_siz = size_in_bytes(l.s);

    p_total.push_back(p_ct_ms);
    l_total.push_back(l_ct_ms);
    l_select_unique.push_back(l.su_t);


    // Delete and deconstruct
    for (size_t i = 1; i < MAXFLOW; i++) {
      cn_f = &root->flow_gh[i - 1];
      for (size_t p = 1; p < MAXFLOW; p++) {
        for (size_t j = 1; j < MAX_PORTS; j++) {
          if (p - 1) {
            cn_p = &(*cn_f)->tcp[j - 1];
          } else {
            cn_p = &(*cn_f)->udp[j - 1];
          }

          if ((*cn_p) != nullptr) {
            if ((*cn_p)->next == nullptr) {
              delete ((*cn_p));
            } else {
              while ((*cn_p)->next != nullptr) {
                cn_p_tmp = *cn_p;
                *cn_p = (*cn_p)->next;
                delete (cn_p_tmp);
              }
              delete (*cn_p);
            }
          }
        }
      }
      delete (*cn_f);
    }
    delete (root);
  }

  const auto Xi_m = (l_total.begin() + l_total.size() / 2);
  const auto Xe_m = (p_total.begin() + p_total.size() / 2);

  std::nth_element(l_total.begin(), Xi_m, l_total.end());
  std::nth_element(p_total.begin(), Xe_m, p_total.end());

  auto We = (float) p_node_size_b;
  auto Xe = (float) *Xe_m;
  auto Wi = (float) alt_b_siz + alt_s_siz + l_vlcp_size_b + l_vlcc_size_b;
  auto Xi = (float) *Xi_m;

  printf("+--[Summary]-------------------------------------------------\n");
  printf("| Samples/runs                          : %d\n", no_samples);
  printf("| No. Signatures in search branch       : %d-%d\n", signo_sb_alt, signo_sb_orig);
  printf("| Filename                              : %s\n", infile);
  printf("| Total No. Signatures                  : %lu \n", sig_list.size());
  printf("| Signature list size                   : %lu\tB\n", sig_size_b);
  printf("| No of unique ports                    : %d\n", unique_ports);
  printf("+--[ORIGINAL representation]----------------------------\n");
  printf("| Size  (We)                            : %.5f KB\n", (float) (We / 1024.0f));
  printf("| Size  (We)                            : %.1f B\n", We);
  printf("| Median search time in ns (Xe)         : %.1f\n", Xe);
  printf("+--[ALTERNATIVE representation]------------------------------------\n");
  printf("| Node relations (B)                    : %d\tB\n", alt_b_siz);
  printf("| Labels (S)                            : %d\tB\n", alt_s_siz);
  printf("| Sig.ref. - VLC vector (bitvector)     : %lu\tB\n", l_vlcp_size_b);
  printf("| Sig.ref. - VLC vector (content)       : %lu\tB\n", l_vlcc_size_b);
  printf("| Total  (Wi)                           : %.5f KB\n", (float) (Wi) / 1024.0f);
  printf("| Total  (Wi)                           : %.1f\n", (Wi));
  printf("| Median search time in ns (Xi)         : %.1f\n", Xi);
  printf("+-[EFFICIENCY]-----------------------------------------------------\n");
  printf("| Space difference (We / Wi)            : %.5f\n", (We / Wi));
  printf("| Time difference  (Xi / Xe)            : %.5f\n", (Xi / Xe));
  printf("| Result     (We * Xe) / (Wi * Xi)      : %.5f\n", (We * Xe) / (Wi * Xi));
  printf("+------------------------------------------------------------------\n");


  for (auto sig : sig_list) {
    free(sig->content);
    free(sig->msg);

    delete (sig); // use delete, because of "new"
  }
  return 0;
}
