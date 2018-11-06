#
# HAC/65 6502 Inferencing Disassembler
#
# This work is licensed under the MIT License <https:#opensource.org/licenses/MIT>
# Copyright 2018 David Hinson <https:#github.com/dhinson919>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
# Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# Portions of this work are derived from the RSA Data Security, Inc. MD5 Message-Digest Algorithm
#

cmake_minimum_required(VERSION 3.9.2)
project(hac65)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXE_LINKER_FLAGS "-static")

include_directories(include)

add_executable(
    hac65
    common.cpp
    common.hpp
    main.cpp
    md5.cpp
    md5.h
    Analyzer.cpp
    Analyzer.hpp
    Hac65.cpp
    Hac65.hpp
    IAnalyzer.hpp
    IHac65.hpp
    ILoader.hpp
    IReporter.hpp
    Loader.cpp
    Loader.hpp
    Reporter.cpp
    Reporter.hpp)
