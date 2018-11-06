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

#ifndef HAC65_IANALYZER_HPP
#define HAC65_IANALYZER_HPP

#include <map>
#include <optional>
#include <string>
#include <vector>

#include "md5.h"

#include "common.hpp"

namespace Hac65
{

struct IAnalyzer
{
    virtual void
    Analyze () = 0;

    virtual void
    DeclareCodeLabel (const std::string &label, const Address &address) = 0;

    virtual void
    DeclareDataLabel (const std::string &label, const Address &address) = 0;

    virtual void
    DeclareEquate (const std::string &equate, const uint16_t &value) = 0;

    virtual void
    DeclareIndirectVectorTable (const Address &address, uint16_t vectorCount) = 0;

    virtual void
    DeclareJumpVectorTable (const Address &address, uint16_t vectorCount) = 0;

    virtual void
    DeclareKeyedIndirectVectorTable (const Address &address, uint16_t vectorCount) = 0;

    virtual void
    DeclareKeyedIndirectMinusOneVectorTable (const Address &address, uint16_t vectorCount) = 0;

    virtual void
    DeclareKeyedVectorTable (const Address &address, uint16_t vectorCount) = 0;

    virtual bool
    DeclareLand (const Address &address) = 0;

    virtual bool
    DeclareLeap (const Address &address) = 0;

    virtual void
    DeclareMinusOneVectorTable (const Address &address, uint16_t vectorCount) = 0;

    virtual void
    DeclareNormalVectorTable (const Address &address, uint16_t vectorCount) = 0;

    virtual void
    DeclareOriginAddress (const Address &address) = 0;

    virtual void
    DeclareSplitVectorTable (const Address &address, uint16_t vectorCount) = 0;

    virtual MD5
    FingerprintCodeSegment (const Segment &segment) const = 0;

    virtual MD5
    FingerprintDataSegment (const Segment &segment) const = 0;

    virtual const std::vector<Octet> &
    GetAssembly () const = 0;

    virtual size_t
    GetAssemblySize () const = 0;

    virtual const std::map<Address, Octet> &
    GetData () const = 0;

    virtual const std::map<Address, Opcode> &
    GetIllegals () const = 0;

    virtual const std::map<Address, Instruction> &
    GetInstructions () const = 0;

    virtual Address
    GetOriginAddress () const = 0;

    virtual const std::map<Address, Segment> &
    GetSegments () const = 0;

    virtual bool
    HasOriginAddress () const = 0;

    virtual const AddressModeInfo &
    LookupAddressModeInfo (const AddressMode &addressMode) const = 0;

    virtual const std::optional<std::vector<std::string>>
    LookupEquate (const uint16_t &value) const = 0;

    virtual const MnemonicInfo &
    LookupMnemonicInfo (const Mnemonic &mnemonic) const = 0;

    virtual const OpcodeInfo &
    LookupOpcodeInfo (const Opcode &opcode) const = 0;

    virtual const std::optional<std::string>
    LookupLabel (const Address &address, std::optional<MemoryOperation> memoryOperationOpt) const = 0;

    virtual void
    SetAssembly (std::vector<Octet> assembly) = 0;

    virtual void
    SetIlluminatingMode () = 0;
};

}

#endif //HAC65_IANALYZER_HPP
