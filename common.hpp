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

#ifndef HAC65_COMMON_HPP
#define HAC65_COMMON_HPP

#include <cassert>
#include <regex>
#include <string>

namespace Hac65
{

using Octet = uint8_t;

using Address = uint16_t;

using Opcode = Octet;

using Operand = uint16_t;

enum Mnemonic
{
    M__Unknown,
    M_ADC, M_AND, M_ASL, M_BCC, M_BCS, M_BEQ, M_BNE, M_BMI, M_BPL, M_BVC,
    M_BVS, M_BIT, M_BRK, M_CLC, M_CLD, M_CLI, M_CLV, M_CMP, M_CPX, M_CPY,
    M_DEC, M_DEX, M_DEY, M_EOR, M_INC, M_INX, M_INY, M_JMP, M_JSR, M_LDA,
    M_LDX, M_LDY, M_LSR, M_NOP, M_ORA, M_PHA, M_PHP, M_PLA, M_PLP, M_ROL,
    M_ROR, M_RTI, M_RTS, M_SBC, M_SEC, M_SED, M_SEI, M_STA, M_STX, M_STY,
    M_TAX, M_TAY, M_TSX, M_TXA, M_TXS, M_TYA
};

struct MnemonicInfo
{
    const std::string _text;
};

enum AddressMode
{
    AM__Unknown,
    AM_Accumulator, // M A
    AM_Absolute,    // M $LLHH
    AM_AbsoluteX,   // M $LLHH,X
    AM_AbsoluteY,   // M $LLHH,Y
    AM_Immediate,   // M #$BB
    AM_Implied,     // M
    AM_Indirect,    // M ($LLHH)
    AM_IndirectX,   // M ($LL,X)
    AM_IndirectY,   // M ($LL),Y
    AM_Relative,    // M $BB
    AM_ZeroPage,    // M $LL
    AM_ZeroPageX,   // M $LL,X
    AM_ZeroPageY    // M $LL,Y
};

struct AddressModeInfo
{
    const u_int8_t _operandSize;
    const char *_operandPrefix;
    const char *_operandSuffix;
};

enum MemoryOperation
{
    MO__Unknown,
    MO_None,
    MO_Read,
    MO_Write,
    MO_Both
};

struct OpcodeInfo
{
    static const Opcode JMP_Absolute{0x4c};

    Mnemonic _mnemonic;
    AddressMode _addressMode;
    MemoryOperation _memoryOperation;
};

struct Instruction
{
    Opcode _opcode;
    OpcodeInfo _opcodeInfo;
    Operand _operand;
};

struct Segment
{
    enum Type
    {
        ST__Unknown = 0,
        ST_CodeDark = 0x01,
        ST_CodeInferred = 0x02,
        ST_CodeKnown = 0x03,
        ST_DataInferred = 0x11,
        ST_DataKnown = 0x12
    };

    Type _type;
    Address _startAddress;
    Address _endAddress;
    size_t _ordinal;

    bool
    IsCode () const
    {
        return !IsData();
    }

    bool
    IsData () const
    {
        return _type & 0x10;
    }
};

extern const char *kUsageText;

extern const char *kVersionText;

uint16_t
FlexIntToUint16 (const std::string &flexInt);

}

#endif //HAC65_COMMON_HPP
