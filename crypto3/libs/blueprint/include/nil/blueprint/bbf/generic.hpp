//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
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
// @file Declaration of interfaces for PLONK BBF context & generic component classes
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_PLONK_BBF_GENERIC_HPP
#define CRYPTO3_BLUEPRINT_PLONK_BBF_GENERIC_HPP

#include <functional>
#include <sstream>
#include <vector>
#include <unordered_map>

#include <boost/log/trivial.hpp>

#include <nil/crypto3/zk/math/expression.hpp>
#include <nil/crypto3/zk/math/expression_visitors.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
// #include <nil/crypto3/zk/snark/arithmetization/plonk/copy_constraint.hpp> // NB: part of the previous include

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
//#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/gate_id.hpp>
#include <nil/blueprint/bbf/allocation_log.hpp>
#include <nil/blueprint/bbf/enums.hpp>
#include <nil/blueprint/bbf/row_selector.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {

            template<typename FieldType>
            class basic_context {
                using assignment_type = nil::crypto3::zk::snark::plonk_assignment_table<FieldType>;
                using assignment_description_type = nil::crypto3::zk::snark::plonk_table_description<FieldType>;

                public:
                    basic_context(const assignment_description_type& desc, std::size_t max_rows_)
                        : current_row{0, 0, 0} // For all types of columns start from 0. TODO: this might not be a good idea
                        , max_rows(max_rows_)
                        , alloc_log(std::make_shared<allocation_log<FieldType>>(desc))
                    {
                        for(std::size_t i = 0; i < desc.witness_columns; i++) {
                            col_map[column_type::witness].push_back(i);
                        }
                        for(std::size_t i = 0; i < desc.public_input_columns; i++) {
                            col_map[column_type::public_input].push_back(i);
                        }
                        for(std::size_t i = 0; i < desc.constant_columns; i++) {
                            col_map[column_type::constant].push_back(i);
                        }
                    }

                    basic_context(const assignment_description_type& desc, std::size_t max_rows_, std::size_t row_shift_)
                        : basic_context(desc, max_rows_) {
                        row_shift = row_shift_;
                    }

                    std::size_t get_col(std::size_t col, column_type t) {
                        if (col >= col_map[t].size()) {
                            std::stringstream ss;
                            ss << "Column ("<< t <<") out of range ("<< col <<" >= " << (col_map[t].size()) << ").";
                            throw std::out_of_range(ss.str());
                        }
                        return col_map[t][col];
                    }

                    std::size_t get_row(std::size_t row) {
                        if (row >= max_rows) {
                            std::stringstream ss;
                            ss << "Row out of range (" << row << " >= " << max_rows << ").";
                            throw std::out_of_range(ss.str());
                        }
                        return row + row_shift;
                    }

                    bool is_allocated(std::size_t col, std::size_t row, column_type t) {
                        return alloc_log->is_allocated(get_col(col,t),get_row(row), t);
                    }

                    void print_witness_allocation_log() {
                        for(std::size_t j = 0; j < col_map[column_type::witness].size(); j++) {
                            std::cout << (j < 10 ? " " : "") << j << " ";
                        }
                        std::cout << "\n";
                        for(std::size_t i = 0; i < max_rows; i++) {
                            for(std::size_t j = 0; j < col_map[column_type::witness].size(); j++) {
                                std::cout << " " << (is_allocated(j, i, column_type::witness) ? "*" : "_") << " ";
                            }
                            std::cout << "\n";
                        }
                    }

                    void mark_allocated(std::size_t col, std::size_t row, column_type t) {
                        alloc_log->mark_allocated(get_col(col,t),get_row(row), t);
                    }

                    std::pair<std::size_t, std::size_t> next_free_cell(column_type t) {
                        std::size_t col = 0,
                                    row = current_row[t],
                                    hsize = col_map[t].size();
                        bool found = false;

                        while ((!found) && (current_row[t] < max_rows)) {
                            if (col >= hsize) {
                                current_row[t]++;
                                row = current_row[t];
                                col = 0;
                            }
                            found = !is_allocated(col,row,t);
                            if (!found) {
                                col++;
                            }
                        }

                        if (!found) {
                            throw std::runtime_error("Insufficient space for allocation.");
                        }

                        return {col, row};
                    }

                    void new_line(column_type t) {
                        while (next_free_cell(t).first > 0) {
                            current_row[t]++;
                            if (current_row[t] == max_rows) {
                                throw std::runtime_error("Insufficient space for starting a new row.");
                            }
                        }
                    }

                private:
                    std::shared_ptr<allocation_log<FieldType>> alloc_log;

                protected:
                    static assignment_description_type add_rows_to_description(
                        const assignment_description_type& input_desc, std::size_t max_rows) {
                        assignment_description_type desc = input_desc;
                        desc.usable_rows_amount += max_rows;
                        desc.rows_amount = std::pow(2, std::ceil(std::log2(desc.usable_rows_amount)));
                        return desc;
                    }

                    std::vector<std::size_t> col_map[column_type::COLUMN_TYPES_COUNT];
                    std::size_t row_shift = 0; // united, for all column types
                    std::size_t max_rows;
                    std::size_t current_row[column_type::COLUMN_TYPES_COUNT];
            };

            template<typename FieldType, GenerationStage stage>
            class context;

            template<typename FieldType>
            class context<FieldType, GenerationStage::ASSIGNMENT> : public basic_context<FieldType> { // assignment-specific definition
            public:
                using TYPE = typename FieldType::value_type;
                using assignment_type = nil::crypto3::zk::snark::plonk_assignment_table<FieldType>;
                using assignment_description_type = nil::crypto3::zk::snark::plonk_table_description<FieldType>;
                using plonk_copy_constraint = crypto3::zk::snark::plonk_copy_constraint<FieldType>;
                using lookup_input_constraints_type = std::vector<TYPE>;
                using lookup_constraint_type = std::pair<std::string, lookup_input_constraints_type>;
                using dynamic_lookup_table_container_type = std::map<std::string,std::pair<std::vector<std::size_t>, row_selector<>>>;
                using basic_context<FieldType>::col_map;
                using basic_context<FieldType>::add_rows_to_description;

                using basic_context<FieldType>::get_col;
                using basic_context<FieldType>::get_row;
                using basic_context<FieldType>::is_allocated;
                using basic_context<FieldType>::mark_allocated;

                context(assignment_type &assignment_table, std::size_t max_rows)
                    : basic_context<FieldType>(add_rows_to_description(assignment_table.get_description(), max_rows), max_rows)
                    , at(assignment_table)
                { };

                context(assignment_type &assignment_table, std::size_t max_rows, std::size_t row_shift)
                    : basic_context<FieldType>(add_rows_to_description(assignment_table.get_description(), max_rows), max_rows, row_shift)
                    , at(assignment_table)
                { };

                void allocate(TYPE &C, size_t col, size_t row, column_type t) {
                    if (is_allocated(col, row, t)) {
                        std::stringstream ss;
                        ss << "RE-allocation of " << t << " cell at col = " << col << ", row = " << row << ".\n";
                        throw std::logic_error(ss.str());
                    }
                    switch (t) {
                        // NB: we use get_col/get_row here because active area might differ
                        // from the entire assignment table, while col and row are intended
                        // to be _relative_ to the active area
                        case column_type::witness:      at.witness(get_col(col,t), get_row(row)) = C;      break;
                        case column_type::public_input: at.public_input(get_col(col,t), get_row(row)) = C; break;
                        case column_type::constant:
                            // constants should already be assigned at this point
                            if (C != at.constant(get_col(col,t), get_row(row))) {
                                BOOST_LOG_TRIVIAL(error) << "Constant " << C << "doesn't match previous assignment "
                                                         << at.constant(get_col(col,t), get_row(row)) << "\n";
                            }
                            BOOST_ASSERT(C == at.constant(get_col(col,t), get_row(row)));
                        break;
                        default:
                           throw std::logic_error("Unknown column type.");
                    }
                    mark_allocated(col, row, t);
                }

                void copy_constrain(const TYPE &A, const TYPE &B) {
#ifdef BLUEPRINT_BBF_VALIDATE_CONSTRAINTS
                    if (A != B) {
                        // NB: This might be an error, but we don't stop execution,
                        // because we want to be able to run tests-to-fail.
                        BOOST_LOG_TRIVIAL(warning) << "Assignment violates copy constraint (" << A << " != " << B << ")";
                    }
#endif
                }
                void constrain(TYPE C, std::string constraint_name, bool big_rotation = false) {
#ifdef BLUEPRINT_BBF_VALIDATE_CONSTRAINTS
                    if (C != 0) {
                        // NB: This might be an error, but we don't stop execution,
                        // because we want to be able to run tests-to-fail.
                        BOOST_LOG_TRIVIAL(warning) << "Assignment violates polynomial constraint "
                                                   << constraint_name << " (" << C << " != 0)";
                    }
#endif
                }
                void lookup(std::vector<TYPE> &C, std::string table_name) {
                    // TODO: actually check membership of C in table?
                }

                void lookup_table(std::string name, std::vector<std::size_t> W, std::size_t from_row, std::size_t num_rows) {
                    multi_lookup_table(name, {W}, from_row, num_rows);
                }

                void multi_lookup_table(std::string name, std::vector<std::vector<std::size_t>> W, std::size_t from_row, std::size_t num_rows) {
                    // most probably do nothing
                }
                context subcontext(const std::vector<std::size_t>& W, std::size_t new_row_shift, std::size_t new_max_rows) {
                    context res = *this;
                    std::vector<std::size_t> new_W = {};
                    for(std::size_t i = 0; i < W.size(); i++) {
                        new_W.push_back(col_map[column_type::witness][W[i]]);
                    }
                    res.col_map[column_type::witness] = new_W;
                    res.row_shift += new_row_shift;
                    res.max_rows = new_max_rows;
                    res.current_row[column_type::witness] = 0; // reset to 0, because in the new column set everything is different
                    return res;
                }

                context fresh_subcontext(const std::vector<std::size_t>& W, std::size_t new_row_shift, std::size_t new_max_rows) {
                    context res = subcontext(W, new_row_shift, new_max_rows);
                    // TODO: Maybe we should create a fresh assignment table here?
                    return res;
                }

                TYPE W(std::size_t col, std::size_t row) {
                    return at.witness(get_col(col, column_type::witness),get_row(row));
                }

                private:
                    // reference to the actual assignment table
                    assignment_type &at;
            };

            // circuit-specific definition
            template<typename FieldType>
            class context<FieldType, GenerationStage::CONSTRAINTS> : public basic_context<FieldType> {
            public:
                using constraint_id_type = gate_id<FieldType>;
                using value_type = typename FieldType::value_type;
                using var = crypto3::zk::snark::plonk_variable<value_type>;
                using constraint_type = crypto3::zk::snark::plonk_constraint<FieldType>;
                using plonk_copy_constraint = crypto3::zk::snark::plonk_copy_constraint<FieldType>;
                using constraints_container_type = std::map<constraint_id_type, std::tuple<constraint_type, row_selector<>, std::set<std::string>>>;
                using global_constraints_container_type = std::map<constraint_id_type, std::pair<constraint_type, std::string>>;
                using copy_constraints_container_type = std::vector<plonk_copy_constraint>; // TODO: maybe it's a set, not a vec?
                using lookup_input_constraints_type = crypto3::zk::snark::lookup_input_constraints<FieldType>;
                using lookup_constraints_container_type = std::map<std::pair<std::string,constraint_id_type>, // <table_name,expressions_id>
                                                                   std::pair<lookup_input_constraints_type, row_selector<>>>;
                                                                   // ^^^ expressions, rows
                using global_lookup_constraints_container_type = std::map<std::pair<std::string,constraint_id_type>, // <table_name,expressions_id>
                                                                   lookup_input_constraints_type>;
                // NB: NOT exactly as plonk!!!
                using lookup_constraint_type = std::pair<std::string, lookup_input_constraints_type>;

                using dynamic_lookup_table_container_type =
                        std::map<std::string, std::pair<std::vector<std::vector<std::size_t>>, row_selector<>>>;
                        //   ^^^ name -> (columns, rows)
                using basic_context<FieldType>::col_map;
                using basic_context<FieldType>::add_rows_to_description;

                using assignment_type = nil::crypto3::zk::snark::plonk_assignment_table<FieldType>;
                using assignment_description_type = nil::crypto3::zk::snark::plonk_table_description<FieldType>;

                using basic_context<FieldType>::row_shift;

                using TYPE = constraint_type;
                using basic_context<FieldType>::get_col;
                using basic_context<FieldType>::get_row;
                using basic_context<FieldType>::is_allocated;
                using basic_context<FieldType>::mark_allocated;

                /**
                 * \param[in] desc - this assignment table description actually shows the used part of the table,
                 *                   and 'max_rows' rows will be added to it.
                 */
                context(const assignment_description_type& desc, std::size_t max_rows)
                        : desc(add_rows_to_description(desc, max_rows))
                        , basic_context<FieldType>(add_rows_to_description(desc, max_rows), max_rows) {
                    reset_storage();
                }

                /**
                 * \param[in] desc - this assignment table description actually shows the used part of the table,
                 *                   and 'max_rows' rows will be added to it.
                 */
                context(const assignment_description_type& desc, std::size_t max_rows, std::size_t row_shift)
                        : desc(add_rows_to_description(desc, max_rows))
                        , basic_context<FieldType>(add_rows_to_description(desc, max_rows), max_rows, row_shift) {
                    reset_storage();
                }

                void allocate(TYPE &C, size_t col, size_t row, column_type t) {
                    if (is_allocated(col, row, t)) {
                    //   BOOST_LOG_TRIVIAL(warning) << "RE-allocation of " << t << " cell at col = " << col << ", row = " << row << ".\n";
                    }
                    if (t == column_type::constant) {
                        auto [has_vars, min_row, max_row] = nil::crypto3::zk::snark::expression_row_range_visitor<var>::row_range(C);
                        if (has_vars) {
                            std::stringstream error;
                            error << "Trying to assign constraint " << C << " to constant cell!";
                            throw std::invalid_argument(error.str());
                        }
                        value_type C_val = C.evaluate(0, *constants_storage);
                        constants_storage->constant(get_col(col,t), get_row(row)) = C_val; // store the constant
                    }
                    var res = var(get_col(col,t), get_row(row), // get_col/get_row are active-area-aware
                                  false, // false = use absolute cell address
                                  static_cast<typename var::column_type>(t));
                    if ((C != TYPE()) && (t == column_type::witness)) { // TODO: TYPE() - is this ok? NB: we only constrain witnesses!
                        constrain(res - C,""); // TODO: maybe add a name for this constraint?
                    }

                    C = res;
                    mark_allocated(col, row, t);
                }

                void copy_constrain(const TYPE &A, const TYPE &B) {
                    auto is_var = nil::crypto3::zk::snark::expression_is_variable_visitor<var>::is_var;

                    if (!is_var(A) || !is_var(B)) {
                        BOOST_LOG_TRIVIAL(error) << "Copy constraint applied to non-variable: " << A << " = " << B << ".\n";
                    }
                    BOOST_ASSERT(is_var(A) && is_var(B));

                    var A_var = boost::get<nil::crypto3::zk::snark::term<var>>(A.get_expr()).get_vars()[0];
                    var B_var = boost::get<nil::crypto3::zk::snark::term<var>>(B.get_expr()).get_vars()[0];

                    if (A_var != B_var) {
                        copy_constraints->push_back({A_var,B_var});
                    }
                }

                TYPE relativize(const TYPE& C, int32_t shift) {
                     auto constraint = C.rotate(shift);
                     if (!constraint)
                         throw std::logic_error("Can't shift the constraint in the given direction.");
                     return *constraint;
                }

                std::vector<TYPE> relativize(const std::vector<TYPE>& C, int32_t shift) {
                    std::vector<TYPE> res;
                    for(const TYPE& c_part : C) {
                        auto constraint = c_part.rotate(shift);
                        if (!constraint)
                            throw std::logic_error("Can't shift the constraint in the given direction.");
                        res.push_back(*constraint);
                    }
                    return res;
                }

                void constrain(const TYPE& C, std::string constraint_name, bool big_rotation = false) {
                    if (!C.is_absolute()) {
                        std::stringstream ss;
                        ss << "Constraint " << C << " has relative variables, cannot constrain.";
                        throw std::logic_error(ss.str());
                    }

                    auto [has_vars, min_row, max_row] = nil::crypto3::zk::snark::expression_row_range_visitor<var>::row_range(C);
                    if (!has_vars) {
                        BOOST_LOG_TRIVIAL(error) << "Constraint " << C << " has no variables!\n";
                    }
                    BOOST_ASSERT(has_vars);
                    if (!big_rotation && max_row - min_row > 2) {
                        BOOST_LOG_TRIVIAL(warning) << "Constraint " << C << " spans over 3 rows!\n";
                    }
                    std::size_t row = (min_row + max_row)/2;

                    std::optional<TYPE> C_rel = C.rotate(-row);
                    if (!C_rel) {
                        throw std::logic_error("Can't shift the constraint in the given direction.");
                    }

                    add_constraint(*C_rel, row, constraint_name);
                }

                // accesible only at GenerationStage::CONSTRAINTS !
                void relative_constrain(TYPE C_rel, std::size_t row, std::string constraint_name = "") {
                    if (!C_rel.is_relative()) {
                        std::stringstream ss;
                        ss << "Constraint " << C_rel << " has absolute variables, cannot constrain.";
                        throw std::logic_error(ss.str());
                    }
                    add_constraint(C_rel, get_row(row), constraint_name);
                }

                void relative_constrain(TYPE C_rel, std::size_t start_row,  std::size_t end_row, std::string constraint_name = "") {
                    if (!C_rel.is_relative()) {
                        std::stringstream ss;
                        ss << "Constraint " << C_rel << " has absolute variables, cannot constrain.";
                        throw std::logic_error(ss.str());
                    }
                    add_constraint(C_rel, get_row(start_row),  get_row(end_row), constraint_name);
                }

                void constrain_all_rows(TYPE C_rel, std::string name = "", bool big_rotation = false) {
                    if (is_subcontext)
                        throw std::logic_error("global constraints are not allowed in subcontexts");

                    if (!C_rel.is_relative()) {
                        std::stringstream ss;
                        ss << "Constraint " << C_rel << " has absolute variables, cannot constrain.";
                        throw std::logic_error(ss.str());
                    }

                    auto [has_vars, min_row, max_row] = nil::crypto3::zk::snark::expression_row_range_visitor<var>::row_range(C_rel);
                    if (!has_vars) {
                        BOOST_LOG_TRIVIAL(error) << "Constraint '" << name << "' has no variables!\n";
                    }
                    BOOST_ASSERT(has_vars);
                    if (!big_rotation && max_row - min_row > 7) {
                        BOOST_LOG_TRIVIAL(warning) << "Constraint " << C_rel << " spans over 7 rows!\n";
                        throw std::logic_error("large constraint");
                    }

                    constraint_id_type C_id = constraint_id_type(C_rel);
                    auto [iter, is_new] = global_constraints->try_emplace(C_id, C_rel, name);
                    if (!is_new) iter->second.second += "," + name;
                }

                void lookup(std::vector<TYPE> &C, std::string table_name) {
                    std::set<std::size_t> base_rows = {};

                    // Choose the best row to relativize. Different expressions in a single lookup might accept
                    // up to 3 different rows for relativization. We take the intersection for all expressions in
                    // the constraint.
                    for(TYPE c_part : C) {
                        auto [has_vars, min_row, max_row] = nil::crypto3::zk::snark::expression_row_range_visitor<var>::row_range(c_part);
                        if (has_vars) { // NB: not having variables seems to be ok for a part of a lookup expression
                            if (max_row - min_row > 2) {
                                BOOST_LOG_TRIVIAL(warning) << "Expression " << c_part << " in lookup constraint spans over 3 rows!\n";
                            }
                            std::size_t row = (min_row + max_row)/2;
                            std::set<std::size_t> current_base_rows = {row};
                            if (max_row - min_row <= 1) {
                                current_base_rows.insert(row+1);
                            }
                            if ((max_row == min_row) && (row > 0)) {
                                current_base_rows.insert(row-1);
                            }
                            if (base_rows.empty()) {
                                base_rows = current_base_rows;
                            } else {
                                std::set<std::size_t> new_base_rows;
                                std::set_intersection(base_rows.begin(), base_rows.end(),
                                                      current_base_rows.begin(), current_base_rows.end(),
                                                      std::inserter(new_base_rows, new_base_rows.end()));
                                base_rows = new_base_rows;
                            }
                        }
                    }
                    if (base_rows.empty()) {
                        BOOST_LOG_TRIVIAL(error) << "Lookup constraint expressions have no variables or have incompatible spans!\n";
                    }
                    BOOST_ASSERT(!base_rows.empty());
                    std::size_t row = (base_rows.size() == 3) ? *(std::next(base_rows.begin())) : *(base_rows.begin());
                    add_lookup_constraint(table_name, relativize(C, -row), row);
                }

                // accesible only at GenerationStage::CONSTRAINTS !
                void relative_lookup(const std::vector<TYPE> &C, std::string table_name, std::size_t row) {
                    for(const TYPE& c_part : C) {
                        if (!c_part.is_relative()) {
                            std::stringstream ss;
                            ss << "Constraint " << c_part << " has absolute variables, cannot constrain.";
                            throw std::logic_error(ss.str());
                        }
                    }
                    add_lookup_constraint(table_name, C, row);
                }

                void relative_lookup(const std::vector<TYPE> &C, std::string table_name, std::size_t start_row, std::size_t end_row) {
                    for(const TYPE& c_part : C) {
                        if (!c_part.is_relative()) {
                            std::stringstream ss;
                            ss << "Constraint " << c_part << " has absolute variables, cannot constrain.";
                            throw std::logic_error(ss.str());
                        }
                    }
                    add_lookup_constraint(table_name, C, start_row, end_row);
                }

                void lookup_all_rows(const std::vector<TYPE> &C, std::string table_name) {
                    if (is_subcontext)
                        throw std::logic_error("global constraints are not allowed in subcontexts");

                    for(const TYPE& c_part : C) {
                        if (!c_part.is_relative()) {
                            std::stringstream ss;
                            ss << "Constraint " << c_part << " has absolute variables, cannot constrain.";
                            throw std::logic_error(ss.str());
                        }
                    }
                    add_global_lookup_constraint(table_name, C);
                }

                void lookup_table(std::string name,
                    std::vector<std::size_t> option,
                    std::size_t from_row, std::size_t num_rows
                ) {
                    multi_lookup_table(name, {option}, from_row, num_rows);
                }

                void multi_lookup_table(std::string name,
                    std::vector<std::vector<std::size_t>> options,
                    std::size_t from_row, std::size_t num_rows
                ) {
                    if (lookup_tables->find(name) != lookup_tables->end() ) {
                        BOOST_LOG_TRIVIAL(error) << "Double declaration of dynamic lookup table '" << name << "'!\n";
                    }
                    BOOST_ASSERT(lookup_tables->find(name) == lookup_tables->end());

                    row_selector<> rows(desc.rows_amount);
                    for(std::size_t i = 0; i < num_rows; i++) {
                        rows.set_row(get_row(from_row + i)); // store absolute row numbers
                    }

                    BOOST_ASSERT(!options.empty());
                    std::size_t n_cols = options[0].size();

                    for (auto &cols : options) {
                        BOOST_ASSERT(cols.size() == n_cols);

                        for (auto &col : cols)
                            col = col_map[column_type::witness][col];
                    }

                    lookup_tables->insert({name, {std::move(options), std::move(rows)}});
                }

                std::unordered_map<row_selector<>, std::vector<std::pair<TYPE, std::string>>> get_constraints() {
                    // joins constraints with identic selectors into a single gate

                    // drop the constraint_id from the stored id->(constraint,row_list) map and
                    // join constrains into single element if they have the same row list:
                    std::unordered_map<row_selector<>, std::vector<std::pair<TYPE, std::string>>> res;
                    for(const auto& [id, data] : *constraints) {
                        auto it = res.find(std::get<1>(data));
                        std::string name;
                        bool first = true;
                        for(auto const &s : std::get<2>(data)){
                            if(first) { name = s; first = false;}
                            else name = name + "," + s;
                        }
                        if (it == res.end()) {
                            res[std::get<1>(data)] = {{std::get<0>(data), name}};
                        } else {
                            it->second.push_back({std::get<0>(data), name});
                        }
                    }
                    return res;
                }

                std::vector<std::pair<TYPE, std::string>> get_global_constraints() {
                    std::vector<std::pair<TYPE, std::string>> res;
                    for (const auto &[id, data] : *global_constraints)
                        res.push_back(data);
                    return res;
                }

                std::vector<plonk_copy_constraint>& get_copy_constraints() {
                    return *copy_constraints;
                }

                dynamic_lookup_table_container_type& get_dynamic_lookup_tables() {
                    return *lookup_tables;
                }

                std::vector<lookup_constraint_type> get_global_lookup_constraints() {
                    std::vector<lookup_constraint_type> res;
                    for (const auto &[id, data] : *global_lookup_constraints)
                        res.push_back(lookup_constraint_type(id.first,data));
                    return res;
                }

                std::unordered_map<row_selector<>, std::vector<lookup_constraint_type>> get_lookup_constraints() {
                    // std::map<std::pair<std::string,constraint_id_type>, // <table_name,expressions_id>
                    //          std::pair<std::vector<constraint_type>,row_selector<>>> // expressions, rows

                    std::unordered_map<row_selector<>, std::vector<lookup_constraint_type>> res;
                    for(const auto& [id, data] : *lookup_constraints) {
                        auto it = res.find(data.second);
		        if (it == res.end()) {
		            res[data.second] = {{id.first, data.first}};
		        } else {
		            it->second.push_back({id.first, data.first});
		        }
                    }

                    /*
                    for(const auto& [lcs, rows] : res) {
                        for(const auto& [table, cs] : lcs) {
                            std::cout << "Table " << table << ": ";
                            for(const auto& c : cs) { std::cout << c << ", "; }
                        }
                        std::cout << "Rows: ";
                        for(const auto& r : rows) { std::cout << r << " "; }
                        std::cout << "\n";
                    }
                    */
                    return res;
                }

                context subcontext(const std::vector<std::size_t>& W, std::size_t new_row_shift, std::size_t new_max_rows) {
                    context res = *this;
                    res.is_subcontext = true;

                    std::vector<std::size_t> new_W = {};
                    for(std::size_t i = 0; i < W.size(); i++) {
                        new_W.push_back(col_map[column_type::witness][W[i]]);
                    }
                    res.col_map[column_type::witness] = new_W;
                    res.row_shift += new_row_shift;
                    res.max_rows = new_max_rows;
                    res.current_row[column_type::witness] = 0; // reset to 0, because in the new column set everything is different
                    return res;
                }

                void reset_storage() {
                    constraints = std::make_shared<constraints_container_type>();
                    global_constraints = std::make_shared<global_constraints_container_type>();
                    copy_constraints = std::make_shared<copy_constraints_container_type>();
                    lookup_constraints = std::make_shared<lookup_constraints_container_type>();
                    global_lookup_constraints = std::make_shared<global_lookup_constraints_container_type>();
                    lookup_tables = std::make_shared<dynamic_lookup_table_container_type>();
                    constants_storage = std::make_shared<assignment_type>(0, 0, desc.constant_columns, 0);
                    is_fresh = false;
                }

                auto get_constants() {
                    return constants_storage->constants();
                }

                // This one will create its own set of constraint storages.
                context fresh_subcontext(const std::vector<std::size_t>& W, std::size_t new_row_shift, std::size_t new_max_rows) {
                    context res = subcontext(W, new_row_shift, new_max_rows);
                    res.reset_storage();
                    is_fresh = true;
                    return res;
                }

            private:
                void add_constraint(TYPE &C_rel, std::size_t row, std::string name) {
                    std::size_t stored_row = row - (is_fresh ? row_shift : 0);
                    constraint_id_type C_id = constraint_id_type(C_rel);
                    if (constraints->find(C_id) == constraints->end()) {
                        constraints->insert({C_id, {C_rel, row_selector<>(desc.rows_amount), {name}}});
                    }
                    std::get<1>(constraints->at(C_id)).set_row(stored_row);
                    std::get<2>(constraints->at(C_id)).insert(name);
                }

                void add_constraint(TYPE &C_rel, std::size_t start_row, std::size_t end_row, std::string name) {
                    std::size_t stored_start_row = start_row - (is_fresh ? row_shift : 0);
                    std::size_t stored_end_row = end_row - (is_fresh ? row_shift : 0);
                    constraint_id_type C_id = constraint_id_type(C_rel);
                    if (constraints->find(C_id) == constraints->end()) {
                        constraints->insert({C_id, {C_rel, row_selector<>(desc.rows_amount), {name}}});
                    }
                    std::get<1>(constraints->at(C_id)).set_interval(stored_start_row, stored_end_row);
                    std::get<2>(constraints->at(C_id)).insert(name);
                }

                void add_lookup_constraint(
                        std::string table_name, const lookup_input_constraints_type &C_rel, std::size_t row) {
                    std::size_t stored_row = row - (is_fresh ? row_shift : 0);
                    constraint_id_type C_id = constraint_id_type(C_rel);
                    std::pair<std::string,constraint_id_type> key = {table_name, C_id};
                    if (lookup_constraints->find(key) == lookup_constraints->end()) {
                        lookup_constraints->insert({
                            key,
                            {C_rel, row_selector<>(desc.rows_amount)}
                        });
                    }
                    lookup_constraints->at(key).second.set_row(stored_row);
                }

                void add_global_lookup_constraint(
                        std::string table_name, const std::vector<TYPE> &C_rel) {
                    constraint_id_type C_id = constraint_id_type(C_rel);
                    std::pair<std::string,constraint_id_type> key = {table_name, C_id};
                    if (global_lookup_constraints->find(key) == global_lookup_constraints->end()) {
                        global_lookup_constraints->insert({ key, C_rel });
                    }
                }

                void add_lookup_constraint(const std::string& table_name, const std::vector<TYPE> &C_rel,
                        std::size_t start_row, std::size_t end_row) {
                    std::size_t stored_start_row = start_row - (is_fresh ? row_shift : 0);
                    std::size_t stored_end_row = end_row - (is_fresh ? row_shift : 0);
                    constraint_id_type C_id = constraint_id_type(C_rel);
                    if (lookup_constraints->find({table_name,C_id}) == lookup_constraints->end()) {
                        lookup_constraints->insert({{table_name,C_id}, {lookup_input_constraints_type(C_rel), row_selector<>(desc.rows_amount)}});
                    }
                    lookup_constraints->at({table_name,C_id}).second.set_interval(stored_start_row, stored_end_row);
                }

                void add_lookup_constraint(std::string table_name, std::vector<TYPE> &C_rel, std::size_t row) {
                    add_lookup_constraint(table_name, lookup_input_constraints_type(C_rel), row);
                }

                // Assignment description will be used when resetting the context.
                assignment_description_type desc;

                bool is_subcontext = false;

                // constraints (with unique id), and the rows they are applied to
                std::shared_ptr<constraints_container_type> constraints;
                // constraints applied to all the rows in the table
                std::shared_ptr<global_constraints_container_type> global_constraints;
                // copy constraints as in BP
                std::shared_ptr<copy_constraints_container_type> copy_constraints;
                // lookup constraints with table name, unique id and row list
                std::shared_ptr<lookup_constraints_container_type> lookup_constraints;
                // lookup constraints applied to all rows with table name, unique id
                std::shared_ptr<global_lookup_constraints_container_type> global_lookup_constraints;
                // dynamic lookup tables
                std::shared_ptr<dynamic_lookup_table_container_type> lookup_tables;
                // constants
                std::shared_ptr<assignment_type> constants_storage;
                // are we in a fresh context or not
                bool is_fresh;
            };

            template<typename FieldType, GenerationStage stage>
            class generic_component {
                public:
                    struct table_params {
                        std::size_t witnesses;
                        std::size_t public_inputs;
                        std::size_t constants;
                        std::size_t rows;
                    };
                    using TYPE = typename std::conditional<static_cast<bool>(stage),
                                 crypto3::zk::snark::plonk_constraint<FieldType>,
                                 typename FieldType::value_type>::type;
                    using context_type = context<FieldType, stage>;
                    using plonk_copy_constraint = crypto3::zk::snark::plonk_copy_constraint<FieldType>;

                private:
                    context_type &ct;

                public:
                static table_params get_minimal_requirements() {
                    return {0,0,0,0};
                }

                void allocate(TYPE &C, column_type t = column_type::witness) {
                    auto [col, row] = ct.next_free_cell(t);
                    ct.allocate(C, col, row, t);
                }

                void allocate(TYPE &C, size_t col, size_t row, column_type t = column_type::witness) {
                    ct.allocate(C,col,row,t);
                }

                void copy_constrain(const TYPE &A, const TYPE &B) {
                    ct.copy_constrain(A,B);
                }

                void constrain(TYPE C, std::string constraint_name = "", bool big_rotation = false) {
                    ct.constrain(C, constraint_name, big_rotation);
                }

                void lookup(std::vector<TYPE> C, std::string table_name) {
                    ct.lookup(C,table_name);
                }

                void lookup(TYPE C, std::string table_name) {
                    std::vector<TYPE> input = {C};
                    ct.lookup(input,table_name);
                }

                void lookup_table(std::string name,
                    std::vector<size_t> option,
                    size_t from_row, size_t num_rows
                ) {
                    multi_lookup_table(name, {option}, from_row, num_rows);
                }

                void multi_lookup_table(std::string name,
                                  std::vector<std::vector<size_t>> options,
                                  size_t from_row, size_t num_rows) {
                    ct.multi_lookup_table(name, options, from_row, num_rows);
                }

                generic_component(context_type &context_object, // context object, created outside
                                  bool crlf = true              // do we assure a component starts on a new row? Default is "yes"
                                 ) : ct(context_object) {
                    if (crlf) { // TODO: Implement crlf parameter consequences
                        ct.new_line(column_type::witness);
                    }
                }
            };

        } // namespace bbf
    } // namespace blueprint
} // namespace nil

#endif // CRYPTO3_BLUEPRINT_PLONK_BBF_GENERIC_HPP
