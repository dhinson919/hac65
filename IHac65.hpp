//
// HAC/65 6502 Inferencing Disassembler
//
// This work is licensed under the MIT License <https://opensource.org/licenses/MIT>
// Copyright 2018 David Hinson <https://github.com/dhinson919>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
// Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// Portions of this work are derived from the RSA Data Security, Inc. MD5 Message-Digest Algorithm
//

#ifndef HAC65_IHAC65_HPP
#define HAC65_IHAC65_HPP

#include <exception>
#include <memory>

#include "IAnalyzer.hpp"
#include "ILoader.hpp"
#include "IReporter.hpp"

namespace Hac65
{

struct IHac65
{
    virtual std::shared_ptr<Hac65::IAnalyzer>
    MakeAnalyzer () = 0;

    virtual std::shared_ptr<Hac65::ILoader>
    MakeLoader () = 0;

    virtual std::shared_ptr<Hac65::IReporter>
    MakeReporter () = 0;
};

IHac65 &
GetHac65 ();

struct Hac65Exception : std::exception
{
    const int _exitCode;
    const std::string _what;

    explicit
    Hac65Exception (std::string what, int exitCode = 1) : _exitCode(exitCode), _what(std::move(what))
    {}

    const char *what () const noexcept override
    {
        return _what.c_str();
    }
};

struct OverlayError : Hac65Exception
{
    explicit
    OverlayError (const std::string &what, int exitCode = 1) :
        Hac65Exception(what, exitCode)
    {}
};

struct UsageError : Hac65Exception
{
    explicit
    UsageError (const std::string &what, int exitCode = 1) :
        Hac65Exception(what, exitCode)
    {}
};

}

#endif //HAC65_IHAC65_HPP
