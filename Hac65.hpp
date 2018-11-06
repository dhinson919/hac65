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

#ifndef HAC65_HAC65_HPP
#define HAC65_HAC65_HPP

#include "IHac65.hpp"
#include "Analyzer.hpp"
#include "Loader.hpp"
#include "Reporter.hpp"

namespace Hac65
{

class Hac65 : public IHac65
{
public:
    std::shared_ptr<IAnalyzer>
    MakeAnalyzer () override
    {
        return std::make_shared<Analyzer>();
    }

    std::shared_ptr<ILoader>
    MakeLoader () override
    {
        return std::make_shared<Loader>();
    }

    std::shared_ptr<IReporter>
    MakeReporter () override
    {
        return std::make_shared<Reporter>();
    }
};

}

#endif //HAC65_HAC65_HPP
