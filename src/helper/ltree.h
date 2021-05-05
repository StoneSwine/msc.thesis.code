/* 
    Inspired by and modified from:
        https://github.com/simongog/sdsl-lite/blob/master/examples/louds-tree.cpp
        by Simon Gog
*/
#ifndef LTREE_H
#define LTREE_H

#include <sdsl/bit_vectors.hpp>
#include "defs.h"
#include <sdsl/wavelet_trees.hpp>

//! Namespace for the succinct data structure library.
using namespace sdsl;
using namespace std::chrono;
using timer = std::chrono::high_resolution_clock;

//! A tree class based on the level order unary degree sequence (LOUDS) representation.
template<class bit_vec_t = bit_vector,
    class select_1_t = typename bit_vec_t::select_1_type,
    class select_0_t = typename bit_vec_t::select_0_type,
    class rank_1_t = typename bit_vec_t::rank_1_type,
    class rank_0_t = typename bit_vec_t::rank_0_type>
class ltree {
public:
  typedef bit_vector::size_type size_type;
  typedef bit_vec_t bit_vector_type;
  typedef select_1_t select_1_type;
  typedef select_0_t select_0_type;
  typedef rank_1_t rank_1_type;
  typedef rank_0_t rank_0_type;

private:
  bit_vector_type m_bv;        // bit vector for the LOUDS sequence
  select_1_type m_bv_select1;  // select support for 1-bits on m_bv
  select_0_type m_bv_select0;  // select support for 0-bits on m_bv
  rank_1_type m_bv_rank1;      // rank support for 1-bits on m_bv
  rank_0_type m_bv_rank0;      // rank support for 0-bits on m_bv
  std::vector<uint32_t> tmp_s; // temporary label storage
  wt_int<bit_vector> S;        // final label storage
  uint select_unique_time = 0;

public:
  const wt_int<bit_vector> &s;
  const bit_vector_type &bv; // const reference to the LOUDS sequence
  const uint &su_t;

  ltree()
      : m_bv(), m_bv_select1(), m_bv_select0(), m_bv_rank1(), m_bv_rank0(), bv(m_bv), s(S), su_t(select_unique_time) {
    bit_vector tmp_bv(2, 0);
    tmp_bv[0] = 1; // 10 in first two spots...
    m_bv = bit_vector_type(std::move(tmp_bv));
  }

  void append(int noc, std::vector<uint32_t> s = {}) {
    if (s.size() != noc) {
      printf("[LTREE][ERROR]: No. child does not match labels");
      return;
    } else {
      bit_vector tmp_bv = m_bv;
      tmp_bv.resize(m_bv.size() + noc + 1);
      size_type pos = m_bv.size();
      if (noc) {
        for (int i = 0; i < noc; i++) {
          tmp_bv[pos++] = 1;
          tmp_s.push_back(s[i]);
        }
      }

      tmp_bv[pos++] = 0;
      tmp_bv.resize(pos);
      m_bv = bit_vector_type(std::move(tmp_bv));
    }
  }

  // Initialise support data structure with rank and select support on bitvectors...
  void finalize() {
    util::init_support(m_bv_select1, &m_bv);
    util::init_support(m_bv_select0, &m_bv);
    util::init_support(m_bv_rank1, &m_bv);
    util::init_support(m_bv_rank0, &m_bv);

    construct_im(S, tmp_s, 4);
    tmp_s.clear();
    tmp_s.shrink_to_fit();
  }

  //! Returns the t'th child of v
  int child(int v, int t) {
    return nodemap(m_bv_select0(m_bv_rank1(v + t)) + 1);
  }

  //! Returns unique identifier in [1,n] for v
  int nodemap(int i) {
    return m_bv_rank0(i);
  }

  //! Converts unique identifier to index in bitvector
  int nodeselect(int v) {
    return m_bv_select0(v) + 1;
  }

  //#define DEBUG
  //! Returns the node identifer for the i'th child labeled l for the node id v
  int labeledchild(int v, uint32_t l) {
    int i = nodeselect(v);
    int s = m_bv_rank1(i) - 1;

    int tmp_s = S.select(S.rank(s, l) + 1, l) - s;
    return child(i, tmp_s);
  }
};

#endif
