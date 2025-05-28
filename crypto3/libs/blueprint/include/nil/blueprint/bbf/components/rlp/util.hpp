//---------------------------------------------------------------------------//
// Copyright (c) 2025 Valeh Farzaliyev <estoniaa@nil.foundation>
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
// copies or substantial portions of the Sof,tware.
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

namespace nil::blueprint::bbf{

    std::size_t extract_next_field_length(const std::vector<std::uint8_t> &buffer, std::size_t start, std::size_t max_bytes){
        std::uint8_t first_byte = buffer[start];
        if(first_byte < 0x80){
            return 1;
        } 
        std::size_t len;
        if(first_byte >= 0x80 && first_byte <= 0xb7){
            len = (std::size_t) (first_byte - 0x80);
        }
        if(first_byte >= 0xb8 && first_byte <= 0xbf){
            std::size_t byte_len_len = (uint8_t) (first_byte - 0xb7);
            len = 0;
            for(std::size_t i = 0; i < byte_len_len; i++){
                len = (len << 8) + buffer[start + i + 1];
            }
        }
        BOOST_ASSERT(len <= max_bytes);
        return len;
    }

    std::vector<std::uint8_t> extract_next_field(std::vector<std::uint8_t> &buffer, std::size_t start, std::size_t max_bytes){
        std::vector<std::uint8_t> result;
        std::uint8_t first_byte = buffer[start];
        if(first_byte < 0x80){
            result.push_back(first_byte);
        } 
        if(first_byte >= 0x80 && first_byte <= 0xb7){
            std::size_t len = (uint8_t) (first_byte - 0x80);
            std::size_t end = start + len + 1;
            end = std::min(end, buffer.size());
            result.insert(result.begin(), buffer.begin() + start, buffer.begin() + end);
        }
        if(first_byte >= 0xb8 && first_byte <= 0xbf){
            std::size_t byte_len_len = (uint8_t) (first_byte - 0xb7);
            std::size_t len = 0;
            for(std::size_t i = 0; i < byte_len_len; i++){
                len = (len << 8) + buffer[start + i + 1];
            }
            
            std::size_t end = start + byte_len_len + len + 1;
            end = std::min(end, buffer.size());
            result.insert(result.begin(), buffer.begin() + start, buffer.begin() + end);
        }
        BOOST_ASSERT(result.size() <= max_bytes);
        return result;
    }
}