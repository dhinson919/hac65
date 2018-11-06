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

#ifndef HAC65_ANALYZER_HPP
#define HAC65_ANALYZER_HPP

#include <functional>
#include <map>
#include <optional>
#include <set>
#include <vector>

#include "IAnalyzer.hpp"
#include "common.hpp"

namespace Hac65
{

class Analyzer : public IAnalyzer
{
    const Address kIrqVector{0xFFFE};
    const Address kResetVector{static_cast<Address>(kIrqVector - 2)};
    const Address kNmiVector{static_cast<Address>(kResetVector - 2)};
    const size_t kMaxAssemblySize{0x10000};
    const Address kDefaultOriginAddress{0};

    const std::unordered_map<Mnemonic, MnemonicInfo> kMnemonicInfos
        {
            {M_ADC, {"ADC"}}, {M_AND, {"AND"}}, {M_ASL, {"ASL"}}, {M_BCC, {"BCC"}}, {M_BCS, {"BCS"}},
            {M_BEQ, {"BEQ"}}, {M_BNE, {"BNE"}}, {M_BMI, {"BMI"}}, {M_BPL, {"BPL"}}, {M_BVC, {"BVC"}},
            {M_BVS, {"BVS"}}, {M_BIT, {"BIT"}}, {M_BRK, {"BRK"}}, {M_CLC, {"CLC"}}, {M_CLD, {"CLD"}},
            {M_CLI, {"CLI"}}, {M_CLV, {"CLV"}}, {M_CMP, {"CMP"}}, {M_CPX, {"CPX"}}, {M_CPY, {"CPY"}},
            {M_DEC, {"DEC"}}, {M_DEX, {"DEX"}}, {M_DEY, {"DEY"}}, {M_EOR, {"EOR"}}, {M_INC, {"INC"}},
            {M_INX, {"INX"}}, {M_INY, {"INY"}}, {M_JMP, {"JMP"}}, {M_JSR, {"JSR"}}, {M_LDA, {"LDA"}},
            {M_LDX, {"LDX"}}, {M_LDY, {"LDY"}}, {M_LSR, {"LSR"}}, {M_NOP, {"NOP"}}, {M_ORA, {"ORA"}},
            {M_PHA, {"PHA"}}, {M_PHP, {"PHP"}}, {M_PLA, {"PLA"}}, {M_PLP, {"PLP"}}, {M_ROL, {"ROL"}},
            {M_ROR, {"ROR"}}, {M_RTI, {"RTI"}}, {M_RTS, {"RTS"}}, {M_SBC, {"SBC"}}, {M_SEC, {"SEC"}},
            {M_SED, {"SED"}}, {M_SEI, {"SEI"}}, {M_STA, {"STA"}}, {M_STX, {"STX"}}, {M_STY, {"STY"}},
            {M_TAX, {"TAX"}}, {M_TAY, {"TAY"}}, {M_TSX, {"TSX"}}, {M_TXA, {"TXA"}}, {M_TXS, {"TXS"}},
            {M_TYA, {"TYA"}}
        };

    const std::unordered_map<AddressMode, AddressModeInfo> kAddressModeInfos
        {
            {AM_Accumulator, {0, "A", ""}},
            {AM_Absolute, {2, "", ""}},
            {AM_AbsoluteX, {2, "", ",X"}},
            {AM_AbsoluteY, {2, "", ",Y"}},
            {AM_Immediate, {1, "#", ""}},
            {AM_Implied, {0, "", ""}},
            {AM_Indirect, {2, "(", ")"}},
            {AM_IndirectX, {1, "(", ",X)"}},
            {AM_IndirectY, {1, "(", "),Y"}},
            {AM_Relative, {1, "", ""}},
            {AM_ZeroPage, {1, "", ""}},
            {AM_ZeroPageX, {1, "", ",X"}},
            {AM_ZeroPageY, {1, "", ",Y"}},
        };

    const std::unordered_map<Opcode, OpcodeInfo> kOpcodeInfos
        {
            {0x69, {M_ADC, AM_Immediate, MO_None}},
            {0x6d, {M_ADC, AM_Absolute, MO_Read}},
            {0x65, {M_ADC, AM_ZeroPage, MO_Read}},
            {0x61, {M_ADC, AM_IndirectX, MO_Read}},
            {0x71, {M_ADC, AM_IndirectY, MO_Read}},
            {0x75, {M_ADC, AM_ZeroPageX, MO_Read}},
            {0x7d, {M_ADC, AM_AbsoluteX, MO_Read}},
            {0x79, {M_ADC, AM_AbsoluteY, MO_Read}},
            {0x29, {M_AND, AM_Immediate, MO_None}},
            {0x2d, {M_AND, AM_Absolute, MO_Read}},
            {0x25, {M_AND, AM_ZeroPage, MO_Read}},
            {0x21, {M_AND, AM_IndirectX, MO_Read}},
            {0x31, {M_AND, AM_IndirectY, MO_Read}},
            {0x35, {M_AND, AM_ZeroPageX, MO_Read}},
            {0x3d, {M_AND, AM_AbsoluteX, MO_Read}},
            {0x39, {M_AND, AM_AbsoluteY, MO_Read}},
            {0x0e, {M_ASL, AM_Absolute, MO_Both}},
            {0x06, {M_ASL, AM_ZeroPage, MO_Both}},
            {0x0a, {M_ASL, AM_Accumulator, MO_None}},
            {0x16, {M_ASL, AM_ZeroPageX, MO_Both}},
            {0x1e, {M_ASL, AM_AbsoluteX, MO_Both}},
            {0x90, {M_BCC, AM_Relative, MO_None}},
            {0xb0, {M_BCS, AM_Relative, MO_None}},
            {0xf0, {M_BEQ, AM_Relative, MO_None}},
            {0xd0, {M_BNE, AM_Relative, MO_None}},
            {0x30, {M_BMI, AM_Relative, MO_None}},
            {0x10, {M_BPL, AM_Relative, MO_None}},
            {0x50, {M_BVC, AM_Relative, MO_None}},
            {0x70, {M_BVS, AM_Relative, MO_None}},
            {0x2c, {M_BIT, AM_Absolute, MO_Read}},
            {0x24, {M_BIT, AM_ZeroPage, MO_Read}},
            {0x00, {M_BRK, AM_Implied, MO_None}},
            {0x18, {M_CLC, AM_Implied, MO_None}},
            {0xd8, {M_CLD, AM_Implied, MO_None}},
            {0x58, {M_CLI, AM_Implied, MO_None}},
            {0xb8, {M_CLV, AM_Implied, MO_None}},
            {0xc9, {M_CMP, AM_Immediate, MO_None}},
            {0xcd, {M_CMP, AM_Absolute, MO_Read}},
            {0xc5, {M_CMP, AM_ZeroPage, MO_Read}},
            {0xc1, {M_CMP, AM_IndirectX, MO_Read}},
            {0xd1, {M_CMP, AM_IndirectY, MO_Read}},
            {0xd5, {M_CMP, AM_ZeroPageX, MO_Read}},
            {0xdd, {M_CMP, AM_AbsoluteX, MO_Read}},
            {0xd9, {M_CMP, AM_AbsoluteY, MO_Read}},
            {0xe0, {M_CPX, AM_Immediate, MO_None}},
            {0xec, {M_CPX, AM_Absolute, MO_Read}},
            {0xe4, {M_CPX, AM_ZeroPage, MO_Read}},
            {0xc0, {M_CPY, AM_Immediate, MO_None}},
            {0xcc, {M_CPY, AM_Absolute, MO_Read}},
            {0xc4, {M_CPY, AM_ZeroPage, MO_Read}},
            {0xce, {M_DEC, AM_Absolute, MO_Both}},
            {0xc6, {M_DEC, AM_ZeroPage, MO_Both}},
            {0xd6, {M_DEC, AM_ZeroPageX, MO_Both}},
            {0xde, {M_DEC, AM_AbsoluteX, MO_Both}},
            {0xca, {M_DEX, AM_Implied, MO_None}},
            {0x88, {M_DEY, AM_Implied, MO_None}},
            {0x49, {M_EOR, AM_Immediate, MO_None}},
            {0x4d, {M_EOR, AM_Absolute, MO_Read}},
            {0x45, {M_EOR, AM_ZeroPage, MO_Read}},
            {0x41, {M_EOR, AM_IndirectX, MO_Read}},
            {0x51, {M_EOR, AM_IndirectY, MO_Read}},
            {0x55, {M_EOR, AM_ZeroPageX, MO_Read}},
            {0x5d, {M_EOR, AM_AbsoluteX, MO_Read}},
            {0x59, {M_EOR, AM_AbsoluteY, MO_Read}},
            {0xee, {M_INC, AM_Absolute, MO_Both}},
            {0xe6, {M_INC, AM_ZeroPage, MO_Both}},
            {0xf6, {M_INC, AM_ZeroPageX, MO_Both}},
            {0xfe, {M_INC, AM_AbsoluteX, MO_Both}},
            {0xe8, {M_INX, AM_Implied, MO_None}},
            {0xc8, {M_INY, AM_Implied, MO_None}},
            {OpcodeInfo::JMP_Absolute, {M_JMP, AM_Absolute, MO_None}},
            {0x6c, {M_JMP, AM_Indirect, MO_None}},
            {0x20, {M_JSR, AM_Absolute, MO_None}},
            {0xa9, {M_LDA, AM_Immediate, MO_None}},
            {0xad, {M_LDA, AM_Absolute, MO_Read}},
            {0xa5, {M_LDA, AM_ZeroPage, MO_Read}},
            {0xa1, {M_LDA, AM_IndirectX, MO_Read}},
            {0xb1, {M_LDA, AM_IndirectY, MO_Read}},
            {0xb5, {M_LDA, AM_ZeroPageX, MO_Read}},
            {0xbd, {M_LDA, AM_AbsoluteX, MO_Read}},
            {0xb9, {M_LDA, AM_AbsoluteY, MO_Read}},
            {0xa2, {M_LDX, AM_Immediate, MO_None}},
            {0xae, {M_LDX, AM_Absolute, MO_Read}},
            {0xa6, {M_LDX, AM_ZeroPage, MO_Read}},
            {0xbe, {M_LDX, AM_AbsoluteY, MO_Read}},
            {0xb6, {M_LDX, AM_ZeroPageY, MO_Read}},
            {0xa0, {M_LDY, AM_Immediate, MO_None}},
            {0xac, {M_LDY, AM_Absolute, MO_Read}},
            {0xa4, {M_LDY, AM_ZeroPage, MO_Read}},
            {0xb4, {M_LDY, AM_ZeroPageX, MO_Read}},
            {0xbc, {M_LDY, AM_AbsoluteX, MO_Read}},
            {0x4e, {M_LSR, AM_Absolute, MO_Both}},
            {0x46, {M_LSR, AM_ZeroPage, MO_Both}},
            {0x4a, {M_LSR, AM_Accumulator, MO_None}},
            {0x56, {M_LSR, AM_ZeroPageX, MO_Both}},
            {0x5e, {M_LSR, AM_AbsoluteX, MO_Both}},
            {0xea, {M_NOP, AM_Implied, MO_None}},
            {0x09, {M_ORA, AM_Immediate, MO_None}},
            {0x0d, {M_ORA, AM_Absolute, MO_Read}},
            {0x05, {M_ORA, AM_ZeroPage, MO_Read}},
            {0x01, {M_ORA, AM_IndirectX, MO_Read}},
            {0x11, {M_ORA, AM_IndirectY, MO_Read}},
            {0x15, {M_ORA, AM_ZeroPageX, MO_Read}},
            {0x1d, {M_ORA, AM_AbsoluteX, MO_Read}},
            {0x19, {M_ORA, AM_AbsoluteY, MO_Read}},
            {0x48, {M_PHA, AM_Implied, MO_None}},
            {0x08, {M_PHP, AM_Implied, MO_None}},
            {0x68, {M_PLA, AM_Implied, MO_None}},
            {0x28, {M_PLP, AM_Implied, MO_None}},
            {0x2e, {M_ROL, AM_Absolute, MO_Both}},
            {0x26, {M_ROL, AM_ZeroPage, MO_Both}},
            {0x2a, {M_ROL, AM_Accumulator, MO_None}},
            {0x36, {M_ROL, AM_ZeroPageX, MO_Both}},
            {0x3e, {M_ROL, AM_AbsoluteX, MO_Both}},
            {0x6e, {M_ROR, AM_Absolute, MO_Both}},
            {0x66, {M_ROR, AM_ZeroPage, MO_Both}},
            {0x6a, {M_ROR, AM_Accumulator, MO_None}},
            {0x76, {M_ROR, AM_ZeroPageX, MO_Both}},
            {0x7e, {M_ROR, AM_AbsoluteX, MO_Both}},
            {0x40, {M_RTI, AM_Implied, MO_None}},
            {0x60, {M_RTS, AM_Implied, MO_None}},
            {0xe9, {M_SBC, AM_Immediate, MO_None}},
            {0xed, {M_SBC, AM_Absolute, MO_Read}},
            {0xe5, {M_SBC, AM_ZeroPage, MO_Read}},
            {0xe1, {M_SBC, AM_IndirectX, MO_Read}},
            {0xf1, {M_SBC, AM_IndirectY, MO_Read}},
            {0xf5, {M_SBC, AM_ZeroPageX, MO_Read}},
            {0xfd, {M_SBC, AM_AbsoluteX, MO_Read}},
            {0xf9, {M_SBC, AM_AbsoluteY, MO_Read}},
            {0x38, {M_SEC, AM_Implied, MO_None}},
            {0xf8, {M_SED, AM_Implied, MO_None}},
            {0x78, {M_SEI, AM_Implied, MO_None}},
            {0x8d, {M_STA, AM_Absolute, MO_Write}},
            {0x85, {M_STA, AM_ZeroPage, MO_Write}},
            {0x81, {M_STA, AM_IndirectX, MO_Write}},
            {0x91, {M_STA, AM_IndirectY, MO_Write}},
            {0x95, {M_STA, AM_ZeroPageX, MO_Write}},
            {0x9d, {M_STA, AM_AbsoluteX, MO_Write}},
            {0x99, {M_STA, AM_AbsoluteY, MO_Write}},
            {0x8e, {M_STX, AM_Absolute, MO_Write}},
            {0x86, {M_STX, AM_ZeroPage, MO_Write}},
            {0x96, {M_STX, AM_ZeroPageY, MO_Write}},
            {0x8c, {M_STY, AM_Absolute, MO_Write}},
            {0x84, {M_STY, AM_ZeroPage, MO_Write}},
            {0x94, {M_STY, AM_ZeroPageX, MO_Write}},
            {0xaa, {M_TAX, AM_Implied, MO_None}},
            {0xa8, {M_TAY, AM_Implied, MO_None}},
            {0xba, {M_TSX, AM_Implied, MO_None}},
            {0x8a, {M_TXA, AM_Implied, MO_None}},
            {0x9a, {M_TXS, AM_Implied, MO_None}},
            {0x98, {M_TYA, AM_Implied, MO_None}}
        };

    struct Land
    {
        Address _address;
        Segment::Type _type;
    };

    friend bool
    operator< (const Analyzer::Land &left, const Analyzer::Land &right);

    std::set<Address> _allVectorAddresses;

    std::map<Address, std::string> _codeLabels;

    std::multimap<Address, std::string> _dataLabels;

    std::multimap<uint16_t, std::string> _equates;

    // { VL -> IL, VH -> VH }
    std::multimap<Address, uint16_t> _indirectVectorTables;

    // { JMP, IL, IH }
    std::multimap<Address, uint16_t> _jumpVectorTables;

    // { <key>, VL -> (IL-1), VH -> IH }
    std::multimap<Address, uint16_t> _keyedIndirectMinusOneVectorTables;

    // { <key>, VL -> IL, VH -> VH }
    std::multimap<Address, uint16_t> _keyedIndirectVectorTables;

    // { <key>, IL, IH }
    std::multimap<Address, uint16_t> _keyedVectorTables;

    // { VL -> (IL-1), VH -> IH }
    std::multimap<Address, uint16_t> _minusOneVectorTables;

    // { IL, IH }
    std::multimap<Address, uint16_t> _normalVectorTables;

    // { IL, +offset:IH }
    std::multimap<Address, uint16_t> _splitVectorTables;

    bool _isIlluminating{false};

    std::vector<Octet> _assembly;

    size_t _assemblySize{0};

    std::optional<Address> _originAddressOpt;

    Address _endAddress{0};

    std::map<Address, Octet> _data;

    std::map<Address, Opcode> _illegals;

    std::map<Address, Instruction> _instructions;

    std::set<Land> _lands;

    std::set<Address> _leaps;

    std::map<Address, Segment> _segments;

    void
    AddData (const Address &address, const Octet &octet)
    {
        _data[address] = octet;
    }

    void
    AddIllegal (const Address &address, const Opcode &opcode)
    {
        _illegals[address] = opcode;
    }

    void
    AddInstruction (const Address &address, const Instruction &instruction)
    {
        _instructions[address] = instruction;
    }

    void
    AddJumpVectorLedges ();

    bool
    AddLand (const Address &address, const Segment::Type &type)
    {
        bool result{false};
        if (address >= GetOriginAddress())
            result = _lands.insert({address, type}).second;
        return result;
    }

    bool
    AddLeap (const Address &address)
    {
        bool result{false};
        if (address >= GetOriginAddress())
            result = _leaps.insert(address).second;
        return result;
    }

    void
    AddSegment (const Address &segmentAddress, const Segment &segment);

    void
    AddVectorIndirections ();

    void
    AddVectorLedges ();

    Address
    AddressToAssemblyOffset (const Address &address) const;

    uint16_t
    DecodeInstructions (
        const Address &startAddress,
        const Address &endAddress,
        const std::function<bool (Address, Instruction)> &legalHandler,
        const std::function<void (Address, Opcode)> &illegalHandler) const;

    void
    ExtractCode ();

    void
    ExtractDarkCode ();

    void
    ExtractData ();

    bool
    InferLedges1 ();

    bool
    InferLedges2 ();

    void
    InferSegments ();

    void
    InitializeAssembly ();

    void
    InitializeLedges ();

    void
    InitializeSegments ()
    {
        _segments.clear();
    }

    void
    RemoveIllegal (const Address &address)
    {
        _illegals.erase(address);
    }

    void
    RemoveInstruction (const Address &address)
    {
        _instructions.erase(address);
    }

    bool
    SegmentHasVectors (const Segment &segment)
    {
        for (const auto &address: _allVectorAddresses)
            if (segment._startAddress <= address && address <= segment._endAddress)
                return true;
            else if (address > segment._endAddress)
                break;
        return false;
    }

    void
    Analyze () override;

    void
    DeclareCodeLabel (const std::string &label, const Address &address) override
    {
        _codeLabels[address] = label;
        DeclareLand(address);
    }

    void
    DeclareDataLabel (const std::string &label, const Address &address) override
    {
        _dataLabels.insert({address, label});
    }

    void
    DeclareEquate (const std::string &equate, const uint16_t &value) override
    {
        _equates.insert({value, equate});
    }

    void
    DeclareIndirectVectorTable (const Address &address, uint16_t vectorCount) override
    {
        _indirectVectorTables.insert({address, vectorCount});
    }

    void
    DeclareJumpVectorTable (const Address &address, uint16_t vectorCount) override
    {
        _jumpVectorTables.insert({address, vectorCount});
    }

    void
    DeclareKeyedIndirectVectorTable (const Address &address, uint16_t vectorCount) override
    {
        _keyedIndirectVectorTables.insert({address, vectorCount});
    }

    void
    DeclareKeyedIndirectMinusOneVectorTable (const Address &address, uint16_t vectorCount) override
    {
        _keyedIndirectMinusOneVectorTables.insert({address, vectorCount});
    }

    void
    DeclareKeyedVectorTable (const Address &address, uint16_t vectorCount) override
    {
        _keyedVectorTables.insert({address, vectorCount});
    }

    bool
    DeclareLand (const Address &address) override
    {
        return AddLand(address, Segment::ST_CodeKnown);
    }

    bool
    DeclareLeap (const Address &address) override
    {
        return AddLeap(address);
    }

    void
    DeclareMinusOneVectorTable (const Address &address, uint16_t vectorCount) override
    {
        _minusOneVectorTables.insert({address, vectorCount});
    }

    void
    DeclareNormalVectorTable (const Address &address, uint16_t vectorCount) override
    {
        _normalVectorTables.insert({address, vectorCount});
    }

    void
    DeclareOriginAddress (const Address &address) override
    {
        _originAddressOpt = std::optional<Address>(address);
    }

    void
    DeclareSplitVectorTable (const Address &address, uint16_t vectorCount) override
    {
        _splitVectorTables.insert({address, vectorCount});
    }

    MD5
    FingerprintCodeSegment (const Segment &segment) const override;

    MD5
    FingerprintDataSegment (const Segment &segment) const override;

    const std::vector<Octet> &
    GetAssembly () const override
    {
        return _assembly;
    }

    size_t
    GetAssemblySize () const override
    {
        return _assemblySize;
    }

    const std::map<Address, Octet> &
    GetData () const override
    {
        return _data;
    }

    const std::map<Address, Opcode> &
    GetIllegals () const override
    {
        return _illegals;
    }

    const std::map<Address, Instruction> &
    GetInstructions () const override
    {
        return _instructions;
    }

    Address
    GetOriginAddress () const override
    {
        return _originAddressOpt.value_or(kDefaultOriginAddress);
    }

    const std::map<Address, Segment> &
    GetSegments () const override
    {
        return _segments;
    }

    bool
    HasOriginAddress () const override
    {
        return _originAddressOpt.has_value();
    }

    const AddressModeInfo &
    LookupAddressModeInfo (const AddressMode &addressMode) const override
    {
        return kAddressModeInfos.at(addressMode);
    }

    const std::optional<std::vector<std::string>>
    LookupEquate (const uint16_t &value) const override;

    const std::optional<std::string>
    LookupLabel (const Address &address, std::optional<MemoryOperation> memoryOperationOpt) const override;

    const MnemonicInfo &
    LookupMnemonicInfo (const Mnemonic &mnemonic) const override
    {
        return kMnemonicInfos.at(mnemonic);
    }

    const OpcodeInfo &
    LookupOpcodeInfo (const Opcode &opcode) const override
    {
        return kOpcodeInfos.at(opcode);
    }

    void
    SetAssembly (std::vector<Octet> assembly) override
    {
        _assembly = std::move(assembly);
        _assemblySize = _assembly.size();
    }

    void
    SetIlluminatingMode () override
    {
        _isIlluminating = true;
    }
};

inline bool
operator< (const Analyzer::Land &left, const Analyzer::Land &right)
{
    return left._address < right._address;
}

}

#endif // HAC65_ANALYZER_HPP
