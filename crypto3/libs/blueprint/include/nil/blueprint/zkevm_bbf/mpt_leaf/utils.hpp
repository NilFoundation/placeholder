//---------------------------------------------------------------------------//
// Copyright (c) 2025 Alexey Yashunsky <a.yashunsky@nil.foundation>
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
#pragma once

#include <nil/crypto3/bench/scoped_profiler.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/bbf/generic.hpp>
#include <nil/blueprint/zkevm_bbf/util.hpp>

namespace nil::blueprint::bbf {

    template<typename FieldType, GenerationStage stage>
    class optimized_selector: public generic_component<FieldType, stage> {
      public:
        using typename generic_component<FieldType, stage>::context_type;
        using generic_component<FieldType, stage>::allocate;
        using generic_component<FieldType, stage>::constrain;

        using typename generic_component<FieldType, stage>::TYPE;

        std::size_t length;
        std::vector<TYPE> x;
        std::vector<TYPE> y;

        optimized_selector(
            context_type &context_object,
            std::size_t _length
        ): generic_component<FieldType, stage>(context_object, false)
         , length(_length) {
            if (length == 32 || length == 33 || length == 34) {
                x.resize(5);
                y.resize(7);
            } else if (length == 8 || length == 9) {
                x.resize(3); 
                y.resize(3);
            } else
                throw "Irregular data length!";
        }

        void allocate_witness(std::size_t &column_index, std::size_t &row_index) {
            for (size_t i = 0; i < x.size(); i++)
                allocate(x[i], column_index++, row_index);
            for (size_t i = 0; i < y.size(); i++)
                allocate(y[i], column_index++, row_index);
        }

        void initialize() {
            for (size_t i = 0; i < x.size(); i++)
                x[i] = 0;
            for (size_t i = 0; i < y.size(); i++)
                y[i] = 0;
        }

        void set_data(std::size_t index) {
            if (length == 32 || length == 33 || length == 34) {
                x[int(index / 7)] = 1;
                y[index % 7] = 1;
            } else if (length == 8 || length == 9) {
                x[int(index / 3)] = 1;
                y[index % 3] = 1;
            } else
                throw "Irregular length!";
        }

        TYPE selector_accumulator(std::size_t index) {
            BOOST_ASSERT_MSG(index >= 0, "Selector index can't be negative!");
            TYPE sum = 0;
            for (size_t i = 0; i <= index; i++)
                sum += this->get_selector(i);
            return sum;
        }

        TYPE get_value() {
            TYPE sum = 0;
            for (size_t i = 0; i < this->length; i++)
                sum += this->get_selector(i) * i;
            return sum;
        }

        TYPE get_selector(std::size_t index) {
            BOOST_ASSERT_MSG(index >= 0, "Selector index can't be negative!");
            if (length == 32 || length == 33 || length == 34)
                return x[int(index/7)] * y[index % 7];
            else if (length == 8 || length == 9)
                return x[int(index/3)] * y[index % 3];
            else
                throw "Irregular length!";
        }

        TYPE selector_is_found() {
            return this->selector_accumulator(this->length - 1);
        }

        void constraints(TYPE value, bool value_should_exist=true) {
            for (size_t i = 0; i < this->length; i++) {
                constrain(this->get_selector(i) * (1 - this->get_selector(i)));
                constrain(this->get_selector(i) * (value - i), "Selector either activates a wrong index or multiple indices!");
            }
            if (value_should_exist) {
                constrain(1 - selector_is_found(), "Only one selector can be active!");
                // constrain(get_value() - value, "Selector activates a wrong value!");
            } else {
                TYPE sum = selector_accumulator(this->length - 1); 
                constrain(sum * (sum - 1), "At most one selector can be active!");
                // for (size_t i = 0; i < this->length; i++)
            }
            _out_of_range_constraints();
            // the following may be necessary if the value is out of range!
            for (size_t i = 0; i < x.size(); i++)
                constrain(x[i] * (1 - x[i]));
            for (size_t i = 0; i < y.size(); i++)
                constrain(y[i] * (1 - y[i]));
        }

        void _out_of_range_constraints() {
            if (length == 32)
                constrain(x[4] * y[5] + x[4] * y[6], "selector out of valid range!");
            else if (length == 33)
                constrain(x[4] * y[6], "selector out of valid range!");
            else if (length == 8)
                constrain(x[2] * y[2], "selector out of valid range!");
        }

        std::string print() {
            std::stringstream ss;
            ss << "selector\n";
            if (this->length == 32 || this->length == 33 || this->length == 34) {
                for (size_t i = 0; i < x.size(); i++)
                    ss << i << "\t" << x[i] << std::endl;
            } else {
                for (size_t i = 0; i < x.size(); i++)
                    ss << i << "\t" << x[i] << std::endl;
                for (size_t i = 0; i < y.size(); i++)
                    ss << i << "\t" << y[i] << std::endl;
            }
            ss << "final selector:\n";
            for (size_t i = 0; i < this->length; i++)
                ss << i << "\t" << get_selector(i) << std::endl;
            return ss.str();
        }
    };
}  // namespace nil::blueprint::bbf
