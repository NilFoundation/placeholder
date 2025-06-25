//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Nikita Kaskov <nbering@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_UTILS_PLONK_SATISFIABILITY_CHECK_HPP
#define CRYPTO3_BLUEPRINT_UTILS_PLONK_SATISFIABILITY_CHECK_HPP

#include <atomic>
#include <functional>
#include <mutex>

#include <boost/asio/thread_pool.hpp>
#include <boost/asio/post.hpp>
#include <boost/thread/thread_only.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/table_description.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/gate.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_gate.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/copy_constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>

namespace nil {
    namespace blueprint {

        struct satisfiability_check_options {
            bool verbose{false};
            size_t thread_pool_size{2 * std::max(boost::thread::hardware_concurrency(), 1u)};
            size_t split_per_thread{16};
            const std::map<uint32_t, std::vector<std::string>>* constraint_names{nullptr}; // non-owning
        };

        template <typename FieldType>
        class satisfiability_checker {

        using Column = crypto3::zk::snark::plonk_column<FieldType>;

        public:
            static bool is_satisfied(
                const circuit<crypto3::zk::snark::plonk_constraint_system<FieldType>>& bp,
                const crypto3::zk::snark::plonk_assignment_table<FieldType> &assignments,
                const satisfiability_check_options &options = {}
            ) {
                satisfiability_checker checker(options);
                return checker.check_assignments(bp, assignments);
            }

        private:
            satisfiability_checker(const satisfiability_check_options &options) : options_(options) {}

            bool check_assignments(
                const circuit<crypto3::zk::snark::plonk_constraint_system<FieldType>>& bp,
                const crypto3::zk::snark::plonk_assignment_table<FieldType> &assignments
            ) {
                std::set<uint32_t> used_gates;
                for (std::uint32_t i = 0; i < bp.gates().size(); i++) {
                    used_gates.insert(i);
                }

                std::set<uint32_t> used_lookup_gates;
                for (std::uint32_t i = 0; i < bp.lookup_gates().size(); i++) {
                    used_lookup_gates.insert(i);
                }

                std::set<uint32_t> used_copy_constraints;
                for (std::uint32_t i = 0; i < bp.copy_constraints().size(); i++) {
                    used_copy_constraints.insert(i);
                }

                std::set<uint32_t> selector_rows;
                for (std::uint32_t i = 0; i < assignments.rows_amount(); i++) {
                    selector_rows.insert(i);
                }

                const auto &gates = bp.gates();
                const auto &copy_constraints = bp.copy_constraints();
                const auto &lookup_gates = bp.lookup_gates();
                const auto verbose = options_.verbose;

                // On MacOS stack size for new threads is too small, so we
                // have to manually specify it to be big enough.
                boost::thread::attributes worker_attrs;
                worker_attrs.set_stack_size(8 << 20);

                const size_t selector_range_per_thread = std::max<size_t>(
                    100,
                    selector_rows.size() / options_.thread_pool_size / options_.split_per_thread // not every batch takes the same time to process, so making it smaller
                );

                if (verbose) BOOST_LOG_TRIVIAL(info) << "Satisfiability check. Check" << std::endl;

                auto gate_check_fn = [
                    &gates,
                    &bp,
                    &assignments,
                    this,
                    verbose
                ] (std::size_t gate_idx, std::size_t start, std::size_t end) -> bool {
                    Column selector;
                    if (auto index = gates[gate_idx].selector_index;
                            index <= crypto3::zk::snark::PLONK_MAX_SELECTOR_ID) {
                        selector = assignments.selector(index);
                    } else if (index == crypto3::zk::snark::PLONK_SPECIAL_SELECTOR_ALL_ROWS_SELECTED) {
                        selector.resize(assignments.rows_amount(), 1);
                    } else {
                      assert(false);
                    }
                    end = std::min(end, selector.size());
                    for (auto row = start; row < end; row++) {
                        if (selector[row].is_zero()) continue;

                        for (std::size_t j = 0; !check_state_.interrupted && j < gates[gate_idx].constraints.size(); j++) {
                            typename FieldType::value_type constraint_result =
                                gates[gate_idx].constraints[j].evaluate(row, assignments);

                            if (!constraint_result.is_zero()) {
                                BOOST_LOG_TRIVIAL(error) << "Constraint " << j << " from gate " << gate_idx << " on row " << row
                                    << " is not satisfied." << std::endl;
                                BOOST_LOG_TRIVIAL(error) << "Constraint result: " << std::hex << constraint_result << std::dec << std::endl;

                                std::string constraint_name;
                                if (options_.constraint_names) {
                                    constraint_name = options_.constraint_names->at(gates[gate_idx].selector_index).at(j);
                                }
                                BOOST_LOG_TRIVIAL(error) << "Offending constraint name: " << constraint_name << std::endl;
                                BOOST_LOG_TRIVIAL(error) << "Offending contraint: " << gates[gate_idx].constraints[j] << std::endl;

                                return false;
                            }
                        }

                        if (verbose) progress_printer_.Increment();
                    }
                    return true;
                };

                for (const auto& i : used_gates) {
                    Column selector;
                    if (auto index = gates[i].selector_index;
                            index <= crypto3::zk::snark::PLONK_MAX_SELECTOR_ID) {
                        selector = assignments.selector(gates[i].selector_index);
                    } else if (index == crypto3::zk::snark::PLONK_SPECIAL_SELECTOR_ALL_ROWS_SELECTED) {
                        selector.resize(assignments.rows_amount(), 1);
                    } else {
                      assert(false);
                    }

                    // To use the attrs we have to create threads manually
                    boost::asio::thread_pool gate_pool(0);
                    std::vector<boost::thread> workers;
                    for (size_t i = 0; i < options_.thread_pool_size; ++i) {
                        workers.emplace_back(worker_attrs, [&gate_pool] () {
                            gate_pool.attach();
                        });
                    }

                    if (verbose) {
                        BOOST_LOG_TRIVIAL(info) << "\tCheck gate " << i << std::endl;
                        progress_printer_.Reset(selector);
                    }

                    for (auto range_start = 0; range_start < selector.size(); range_start += selector_range_per_thread) {
                        boost::asio::post(gate_pool, [=, &gate_check_fn, this] () {
                            if (!gate_check_fn(i, range_start, range_start + selector_range_per_thread)) {
                                check_state_.set_failed();
                            }
                        });
                    }

                    gate_pool.wait();
                    for (auto &w : workers) w.join();

                    if (!check_state_.result) {
                        return check_state_.result;
                    }

                    if (verbose) {
                        BOOST_LOG_TRIVIAL(info) << "\tGate " << i << " checked" << std::endl;
                    }
                }

                if (verbose) {
                    BOOST_LOG_TRIVIAL(info) << "Gates checked. Check lookups" << std::endl;
                }

                auto lookup_check_fn = [
                    &lookup_gates,
                    &assignments,
                    &bp,
                    verbose,
                    this
                ](size_t gate_idx, size_t start, size_t end) -> bool {
                    Column selector;
                    auto index = lookup_gates[gate_idx].tag_index;
                    if ( index <= crypto3::zk::snark::PLONK_MAX_SELECTOR_ID) {
                        selector = assignments.selector(index);
                    } else if (index == crypto3::zk::snark::PLONK_SPECIAL_SELECTOR_ALL_ROWS_SELECTED) {
                        selector.resize(assignments.rows_amount(), 1);
                    } else {
                        assert(false);
                    }
                    end = std::min(end, selector.size());

                    for (size_t row = start; row < end; ++row) {
                        if (selector[row].is_zero()) continue;

                        for (std::size_t j = 0; !check_state_.interrupted && j < lookup_gates[gate_idx].constraints.size(); j++) {

                            std::vector<typename FieldType::value_type> input_values;
                            input_values.reserve(lookup_gates[gate_idx].constraints[j].lookup_input.size());
                            for (std::size_t k = 0; k < lookup_gates[gate_idx].constraints[j].lookup_input.size(); k++) {
                                input_values.emplace_back(lookup_gates[gate_idx].constraints[j].lookup_input[k].evaluate(
                                    row, assignments));
                            }
                            const auto table_name =
                                bp.get_reserved_indices_right().at(lookup_gates[gate_idx].constraints[j].table_id);

                            try {
                                if(bp.get_reserved_dynamic_tables().find(table_name) != bp.get_reserved_dynamic_tables().end() ) {
                                    auto dynamic_table = fetch_dynamic_table(bp, assignments, table_name, lookup_gates[gate_idx].constraints[j].table_id);
                                    if (dynamic_table.find(input_values) == dynamic_table.end()) {
                                        BOOST_LOG_TRIVIAL(error) << "Input values";
                                        std::stringstream ss;
                                        for (std::size_t k = 0; k < input_values.size(); k++) {
                                            ss << std::hex << input_values[k] << std::dec << " ";
                                        }
                                        BOOST_LOG_TRIVIAL(error) << ss.str();
                                        BOOST_LOG_TRIVIAL(error) << std::endl;
                                        BOOST_LOG_TRIVIAL(error) << "Constraint " << j << " from lookup gate " << gate_idx << " from table "
                                            << table_name << " on row " << row << " is not satisfied."
                                            << std::endl;
                                        BOOST_LOG_TRIVIAL(error) << "Offending Lookup Constraint: " << std::endl;
                                        const auto &constraint = lookup_gates[gate_idx].constraints[j];
                                        BOOST_LOG_TRIVIAL(error) << "Table id: " << constraint.table_id << std::endl;
                                        for (auto &lookup_input : constraint.lookup_input) {
                                            BOOST_LOG_TRIVIAL(debug) << lookup_input;
                                        }
                                        // Please not comment it next time, it is really useful for circuits debugging
                                        BOOST_LOG_TRIVIAL(trace) << "Possible values: ";
                                        for( const auto &row: dynamic_table ) {
                                            std::stringstream ss;
                                            for( const auto &value : row ) {
                                                ss << std::hex << value << std::dec << " ";
                                            }
                                            BOOST_LOG_TRIVIAL(trace) << ss.str();
                                        }

                                        return false;
                                    }
                                    continue;
                                }
                                std::string main_table_name = table_name.substr(0, table_name.find("/"));
                                std::string subtable_name = table_name.substr(table_name.find("/") + 1, table_name.size() - 1);

                                const auto &table = bp.get_reserved_tables().at(main_table_name)->get_table();
                                const auto &subtable = bp.get_reserved_tables().at(main_table_name)->subtables.at(subtable_name);

                                std::size_t columns_number = subtable.column_indices.size();

                                // Search the table for the input values
                                // We can cache it with sorting, or use KMP, but I need a simple solution first
                                bool found = false;
                                BOOST_ASSERT(columns_number == input_values.size());
                                for (std::size_t k = 0; k < table[0].size(); k++) {
                                    bool match = true;
                                    for (std::size_t l = 0; l < columns_number; l++) {
                                        if (table[subtable.column_indices[l]][k] != input_values[l]) {
                                            match = false;
                                            break;
                                        }
                                    }
                                    if (match) {
                                        found = true;
                                        break;
                                    }
                                }
                                if (!found) {
                                    BOOST_LOG_TRIVIAL(error) << "Input values:";
                                    std::stringstream ss;
                                    for (std::size_t k = 0; k < input_values.size(); k++) {
                                        ss << std::hex << input_values[k] << std::dec <<  " ";
                                    }
                                    BOOST_LOG_TRIVIAL(error) << ss.str();
                                    BOOST_LOG_TRIVIAL(error) << std::endl;
                                    BOOST_LOG_TRIVIAL(error) << "Constraint " << j << " from lookup gate " << gate_idx << " from table "
                                        << table_name << " on row " << row << " is not satisfied."
                                        << std::endl;
                                    BOOST_LOG_TRIVIAL(error) << "Offending Lookup Constraint: " << std::endl;
                                    const auto &constraint = lookup_gates[gate_idx].constraints[j];
                                    BOOST_LOG_TRIVIAL(error) << "Table id: " << constraint.table_id << std::endl;
                                    for (auto &lookup_input : constraint.lookup_input) {
                                        BOOST_LOG_TRIVIAL(error) << lookup_input << std::endl;
                                    }
                                    return false;
                                }
                            } catch (std::out_of_range &e) {
                                BOOST_LOG_TRIVIAL(error) << "Lookup table " << table_name << " not found." << std::endl;
                                BOOST_LOG_TRIVIAL(error) << "Table_id = " << lookup_gates[gate_idx].constraints[j].table_id << " table_name "
                                            << table_name << std::endl;

                                return false;
                            }
                        }

                        if (verbose) progress_printer_.Increment();
                    }
                    return true;
                };

                for (const auto& i : used_lookup_gates) {
                    Column selector;
                    auto index = lookup_gates[i].tag_index;
                    if ( index <= crypto3::zk::snark::PLONK_MAX_SELECTOR_ID) {
                        selector = assignments.selector(index);
                    } else if (index == crypto3::zk::snark::PLONK_SPECIAL_SELECTOR_ALL_ROWS_SELECTED) {
                        selector.resize(assignments.rows_amount(), 1);
                    } else {
                        assert(false);
                    }

                    // To use the attrs we have to create threads manually
                    boost::asio::thread_pool lookup_pool(0);
                    std::vector<boost::thread> workers;
                    for (size_t i = 0; i < options_.thread_pool_size; ++i) {
                        workers.emplace_back(worker_attrs, [&lookup_pool] () {
                            lookup_pool.attach();
                        });
                    }

                    if (verbose) {
                        BOOST_LOG_TRIVIAL(info) << "\tLookup gate " << i << std::endl;
                        progress_printer_.Reset(selector);
                    }

                    for (auto range_start = 0; range_start < selector.size(); range_start += selector_range_per_thread) {
                        boost::asio::post(lookup_pool, [=, &lookup_check_fn, this] () {
                            if (!lookup_check_fn(i, range_start, range_start + selector_range_per_thread)) {
                                check_state_.set_failed();
                            }
                        });
                    }

                    lookup_pool.wait();
                    for (auto &w : workers) w.join();

                    if (!check_state_.result) {
                        return check_state_.result;
                    }

                    if (verbose) {
                        BOOST_LOG_TRIVIAL(info) << "\tLookup gate " << i << " checked" << std::endl;
                    }
                }

                for (const auto& i : used_copy_constraints) {
                    if (var_value(assignments, copy_constraints[i].first) !=
                        var_value(assignments, copy_constraints[i].second)) {
                        BOOST_LOG_TRIVIAL(error) << "Copy constraint number " << i << " is not satisfied."
                                    << " First variable: " << copy_constraints[i].first
                                    << " second variable: " << copy_constraints[i].second << std::endl;
                        BOOST_LOG_TRIVIAL(error) << var_value(assignments, copy_constraints[i].first) << " != "
                                    << var_value(assignments, copy_constraints[i].second) << std::endl;
                        return false;
                    }
                }

                return true;
            }

            std::set<std::vector<typename FieldType::value_type>>
            fetch_dynamic_table(
                const circuit<crypto3::zk::snark::plonk_constraint_system<FieldType>> &bp,
                const crypto3::zk::snark::plonk_assignment_table<FieldType> &assignments,
                const std::string& table_name,
                std::size_t table_id
            ) {
                auto ret = used_dynamic_tables_.find(table_name);
                if (ret != used_dynamic_tables_.end()) {
                    return ret->second;
                }

                {
                    std::lock_guard<std::mutex> lock(used_dynamic_tables_mutex_);
                    ret = used_dynamic_tables_.find(table_name);
                    if (ret != used_dynamic_tables_.end()) {
                        return ret->second;
                    }
                    used_dynamic_tables_[table_name] = load_dynamic_lookup(bp, assignments, table_id);
                    return used_dynamic_tables_[table_name];
                }
            };

            std::set<std::vector<typename FieldType::value_type>>
            load_dynamic_lookup(
                const circuit<crypto3::zk::snark::plonk_constraint_system<FieldType>> &bp,
                const crypto3::zk::snark::plonk_assignment_table<FieldType> &assignments,
                std::size_t table_id
            ) {
                std::set<std::vector<typename FieldType::value_type>> result;
                auto &table = bp.lookup_tables()[table_id-1];

                crypto3::zk::snark::plonk_column<FieldType> selector = assignments.selector(table.tag_index);

                for( std::size_t selector_row = 0; selector_row < assignments.rows_amount(); selector_row++ ){
                    if( selector_row < selector.size() && !selector[selector_row].is_zero() ){
                        for( std::size_t op = 0; op < table.lookup_options.size(); op++){
                            std::vector<typename FieldType::value_type> item(table.lookup_options[op].size());
                            for( std::size_t i = 0; i < table.lookup_options[op].size(); i++){
                                crypto3::zk::snark::plonk_constraint<FieldType> expr = table.lookup_options[op][i];;
                                item[i] = expr.evaluate(selector_row, assignments);
                            }
                            result.insert(item);
                        }
                    }
                }
                return result;
            }

        private:
            class progress_printer {
                public:
                void Reset(const Column &c) {
                    total_ = 0;
                    processed_ = 0;
                    progress_ = 0;

                    for (const auto &s : c)
                        if (!s.is_zero()) ++total_;
                }

                void Increment() {
                    assert(processed_ < total_);

                    auto processed = ++processed_;
                    auto total = total_.load();

                    if (progress_.load() < kMaxProgress * processed / total) {
                        std::lock_guard lock(cout_mutex);
                        while (progress_.load() < kMaxProgress * processed / total) {
                            std::cout << '.' << std::flush;
                            ++progress_;
                        }

                        if (progress_.load() == kMaxProgress) {
                            std::cout << '\n';
                        }
                    }
                }

            private:
                const size_t kMaxProgress = 80;

                std::atomic_size_t total_ = 0;
                std::atomic_size_t progress_{0};
                std::atomic_size_t processed_{0};

                std::mutex cout_mutex;
            };

            struct check_state {
                bool interrupted{false};
                bool result{true};

                void set_failed() {
                    interrupted = true;
                    result = false;
                }
            };

        private:
            const satisfiability_check_options& options_;
            std::mutex used_dynamic_tables_mutex_;
            std::map<std::string, std::set<std::vector<typename FieldType::value_type>>> used_dynamic_tables_;
            progress_printer progress_printer_;
            check_state check_state_;
        };
    }    // namespace blueprint
}    // namespace nil
#endif    // CRYPTO3_BLUEPRINT_UTILS_PLONK_SATISFIABILITY_CHECK_HPP
