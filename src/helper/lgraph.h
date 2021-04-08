#ifndef LGRAPH_H
#define LGRAPH_H
#include <sdsl/bit_vectors.hpp>
#include "defs.h"
#include <sdsl/wavelet_trees.hpp>

//! Namespace for the succinct data structure library.
using namespace sdsl;
using namespace std::chrono;
using timer = std::chrono::high_resolution_clock;

template <class bit_vec_t = bit_vector>
class lgraph
{
public:
    typedef bit_vec_t bit_vector_type;

private:
    bit_vector::rank_1_type b_rank1;

    bit_vector_type b;
    bit_vector_type bl;

    std::vector<uint> tmp_l; // temporary label storage
    vlc_vector<VLC_CODER> L; // final label storage
    std::vector<uint> tmp_n; // temporary label storage
    vlc_vector<VLC_CODER> N; // final label storage

public:
    const vlc_vector<VLC_CODER> &l;
    const bit_vector_type &bv; // const reference to the LOUDS sequence

    lgraph() : b(), bl(), bv(b), l(L)
    {
        b = bit_vector_type();
        bl = bit_vector_type();
    }

    void appendLabel(std::vector<uint> labels = {})
    {
        bit_vec_t tmp_bv = b;
        tmp_bv.resize(b.size() + labels.size() + 1);
        tmp_bv[(b.size()) + 1] = 1;
        b = bit_vector_type(std::move(tmp_bv));
        for (auto i : labels)
        {
            tmp_l.push_back(i);
        }
    }

    void appendDistNodeN(std::vector<uint> nodes = {})
    {
        bit_vector_type tmp_bv = bl;
        tmp_bv.resize(bl.size() + nodes.size() + 1);
        tmp_bv[(bl.size()) + 1] = 1;
        bl = bit_vector_type(std::move(tmp_bv));
        for (auto i : nodes)
        {
            tmp_n.push_back(i);
        }
    }

    // Initialise support data structure with rank and select support on bitvectors...
    void finalize()
    {
        std::cout << "finializing" << std::endl;

        b_rank1(&b);

        std::cout << tmp_l.size() << " " << tmp_n.size() << " " << b.size() << " " << bl.size() << std::endl;

        L = vlc_vector<VLC_CODER>(std::move(tmp_l));
        N = vlc_vector<VLC_CODER>(std::move(tmp_n));

        tmp_l.clear();
        tmp_l.shrink_to_fit();
        tmp_n.clear();
        tmp_n.shrink_to_fit();
    }
};

#endif
