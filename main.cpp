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

#include <cstdlib>
#include <getopt.h>
#include <sstream>

#include "IHac65.hpp"
using namespace Hac65;

static uint16_t
ParseDigitsArg (const char *pFailText)
{
    uint16_t result{};
    try
    {
        result = FlexIntToUint16(::optarg);
    }
    catch (const Hac65Exception &exc)
    {
        std::string what{pFailText};
        what += exc.what();
        throw UsageError(what);
    }
    return result;
}

int
main (int argc, char *argv[])
{
    IHac65 &hac65{GetHac65()};
    auto pAnalyzer{hac65.MakeAnalyzer()};
    auto pLoader{hac65.MakeLoader()};
    auto pReporter{hac65.MakeReporter()};

    try
    {
        int opt{};
        while ((opt = ::getopt(argc, argv, "hvS:E:A:o:iR:")) != -1)
        {
            switch (opt)
            {
                // General options:
                case 'h': throw UsageError(kUsageText, 0);
                case 'v': throw UsageError(kVersionText, 0);

                // Loader options:
                case 'S':
                    {
                        uint16_t value{ParseDigitsArg("-S arg contains ")};
                        pLoader->SetStartPosition(value);
                    }
                    break;
                case 'E':
                    {
                        uint16_t value{ParseDigitsArg("-E arg contains ")};
                        pLoader->SetEndPosition(value);
                    }
                    break;
                case 'A': pLoader->SetArchitecture(::optarg); break;

                // Analyzer options:
                case 'o':
                    {
                        uint16_t value{ParseDigitsArg("-o arg contains ")};
                        pAnalyzer->DeclareOriginAddress(value);
                    }
                    break;
                case 'i': pAnalyzer->SetIlluminatingMode(); break;

                // Reporter options:
                case 'R': pReporter->SetReportFlags(::optarg); break;

                default: throw UsageError(kUsageText);
            }
        }
        if (argc < 2)
            throw UsageError(kUsageText);

        std::string objectFilename;
        if (argc == ::optind)
            throw UsageError(kUsageText);
        else if (argc > ::optind)
        {
            if (argc - ::optind > 1)
                throw UsageError(kUsageText);
            objectFilename = argv[::optind];
        }
        pLoader->SetObjectFilename(objectFilename);

        // Load object file:
        pLoader->Load(pAnalyzer);

        // Analyze assembly:
        pAnalyzer->Analyze();

        // Report findings:
        std::string timeStr;
        {
            const ::time_t unixTime{::time(nullptr)};
            const struct tm *pTm{::gmtime(&unixTime)};
            char buf[25];
            strftime(buf, sizeof buf, "%c", pTm);
            timeStr = buf;
        }
        std::ostringstream command;
        for (auto count{0}; count < argc; ++count)
            if (count == 0)
            {
                char *pSeperator{::strrchr(argv[count], '/')};
                command << (pSeperator ? pSeperator + 1 : argv[count]);
            }
            else
                command << ' ' << argv[count];
        pReporter->Report(pLoader, pAnalyzer, timeStr, command.str(), std::cout);
    }
    catch (const Hac65Exception &exc)
    {
        const char *what{exc.what()};
        if (what != nullptr)
        {
            if (exc._exitCode != 0)
                std::cerr << "Error: ";
            std::cerr << what << std::endl;
        }
        ::exit(exc._exitCode);
    }
    catch (const std::exception &exc)
    {
        const char *what{exc.what()};
        if (what != nullptr)
            std::cerr << "Unusual Error: " << what << std::endl;
        ::exit(1);
    }

    return 0;
}
