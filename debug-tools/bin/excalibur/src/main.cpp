// MIT License
//
// Copyright (c) 2023 Dmitrii Tabalin <d.tabalin@nil.foundation>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <gtkmm/application.h>

#include <giomm/menu.h>

#include <glibmm/optioncontext.h>
#include <glibmm/optiongroup.h>

#include <numeric>

#include <nil/crypto3/algebra/fields/vesta/base_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/pallas/base_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>

#include <nil/crypto3/algebra/fields/mnt4/base_field.hpp>
#include <nil/crypto3/algebra/fields/mnt6/base_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/goldilocks64.hpp>
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/alt_bn128/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>

#include "table.hpp"

int main(int argc, char* argv[]) {
    auto app = Gtk::Application::create("foundation.nil.excalibur");

    using vesta_curve_type = nil::crypto3::algebra::curves::vesta::base_field_type;
    using pallas_curve_type = nil::crypto3::algebra::curves::pallas::base_field_type;
    using bls12_fr_381_curve_type = nil::crypto3::algebra::fields::bls12_fr<381>;
    using bls12_fq_381_curve_type = nil::crypto3::algebra::fields::bls12_fq<381>;
    using mnt4_curve_type = nil::crypto3::algebra::fields::mnt4_fq<298>;
    using mnt6_curve_type = nil::crypto3::algebra::fields::mnt6_fq<298>;
    using goldilocks64_field_type = nil::crypto3::algebra::fields::goldilocks64;
    using bn_base_field_type = nil::crypto3::algebra::fields::alt_bn128<254>;
    using bn_scalar_field_type = nil::crypto3::algebra::fields::alt_bn128_scalar_field<254>;

    Glib::OptionGroup::vecustrings main_option_vector;
    Glib::OptionGroup main_group("curves", "Curves", "Curve used in the program");

    bool vesta = false, pallas = false, bls12_fr_381 = false, bls12_fq_381 = false,
         mnt4 = false, mnt6 = false, goldilocks64 = false, bn_base = false, bn_scalar = false;
    Glib::OptionEntry vesta_entry, pallas_entry, bls12_fr_381_entry, bls12_fq_381_entry,
                      mnt4_entry, mnt6_entry, goldilocks64_entry, bn_entry;

    vesta_entry.set_long_name("vesta");
    vesta_entry.set_short_name('v');
    vesta_entry.set_description("Use Vesta curve");
    main_group.add_entry(vesta_entry, vesta);

    pallas_entry.set_long_name("pallas");
    pallas_entry.set_short_name('p');
    pallas_entry.set_description("Use Pallas curve");
    main_group.add_entry(pallas_entry, pallas);

    bls12_fr_381_entry.set_long_name("bls12_fr_381");
    bls12_fr_381_entry.set_short_name('b');
    bls12_fr_381_entry.set_description("Use BLS12_fr_381 curve");
    main_group.add_entry(bls12_fr_381_entry, bls12_fr_381);

    bls12_fq_381_entry.set_long_name("bls12_fq_381");
    bls12_fq_381_entry.set_short_name('q');
    bls12_fq_381_entry.set_description("Use BLS12_fq_381 curve");
    main_group.add_entry(bls12_fq_381_entry, bls12_fq_381);

    mnt4_entry.set_long_name("mnt4");
    mnt4_entry.set_short_name('4');
    mnt4_entry.set_description("Use mnt4 curve");
    main_group.add_entry(mnt4_entry, mnt4);

    mnt6_entry.set_long_name("mnt6");
    mnt6_entry.set_short_name('6');
    mnt6_entry.set_description("Use mnt6 curve");
    main_group.add_entry(mnt6_entry, mnt6);

    goldilocks64_entry.set_long_name("goldilocks64");
    goldilocks64_entry.set_short_name('g');
    goldilocks64_entry.set_description("Use Goldilocks64 curve");
    main_group.add_entry(goldilocks64_entry, goldilocks64);

    bn_entry.set_long_name("bn");
    bn_entry.set_short_name('n');
    bn_entry.set_description("Use BN curve base field");
    main_group.add_entry(bn_entry, bn_base);

    bn_entry.set_long_name("bn_scalar");
    bn_entry.set_short_name('s');
    bn_entry.set_description("Use BN curve scalar field");
    main_group.add_entry(bn_entry, bn_scalar);

    // Add the main group to the context
    Glib::OptionContext context;
    context.set_main_group(main_group);
    context.set_help_enabled(true);
    context.set_ignore_unknown_options(true);
    context.parse(argc, argv);

    // check that only a single curve is selected
    std::vector<bool> curve_selections = {
        vesta, pallas, bls12_fr_381, bls12_fq_381,mnt4, mnt6, goldilocks64,
        bn_base, bn_scalar};
    uint8_t curve_count = std::accumulate(curve_selections.begin(), curve_selections.end(), 0);
    if (curve_count > 1) {
        std::cerr << "Error: only one curve can be used at a time." << std::endl;
        return 1;
    }
    // check that at least one curve is selected
    if (curve_count == 0) {
        std::cerr << "Error: no curve selected. Use --vesta or --pallas or --bls12_fr_381, or --bls12_fq_381"
                  << " or --mnt4 or --mnt6 or --goldilocks64, or --bn, or --bn_scalar."
                  << std::endl;
        return 1;
    }

    if (vesta) {
        return app->make_window_and_run<ExcaliburWindow<vesta_curve_type>>(argc, argv);
    }
    if (pallas) {
        return app->make_window_and_run<ExcaliburWindow<pallas_curve_type>>(argc, argv);
    }
    if (bls12_fr_381) {
        return app->make_window_and_run<ExcaliburWindow<bls12_fr_381_curve_type>>(argc, argv);
    }
    if (bls12_fq_381) {
        return app->make_window_and_run<ExcaliburWindow<bls12_fq_381_curve_type>>(argc, argv);
    }
    if (mnt4) {
        return app->make_window_and_run<ExcaliburWindow<mnt4_curve_type>>(argc, argv);
    }
    if (mnt6) {
        return app->make_window_and_run<ExcaliburWindow<mnt6_curve_type>>(argc, argv);
    }
    if (goldilocks64) {
        return app->make_window_and_run<ExcaliburWindow<goldilocks64_field_type>>(argc, argv);
    }
    if (bn_base) {
        return app->make_window_and_run<ExcaliburWindow<bn_base_field_type>>(argc, argv);
    }
    if (bn_scalar) {
        return app->make_window_and_run<ExcaliburWindow<bn_scalar_field_type>>(argc, argv);
    }
}
