using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Reflection.Emit;

namespace EpiSource.KeePass.Ekf.Util {
    public static class ILOpcodeLut {
        
        public sealed class OpCodeInfo {
            private readonly OpCode opCode;
            private readonly int operandSize;
            private readonly int operandValue;

            internal OpCodeInfo(OpCode opCode, int operandSize, int operandValue) {
                if (opCode.Size == 0) {
                    throw new ArgumentException("opCode.Size == 0", "opCode");
                }
                if (operandSize < 0) {
                    throw new ArgumentException("operandSize < 0");
                }
                
                this.opCode = opCode;
                this.operandSize = operandSize;
                this.operandValue = operandValue;
            }

            public OpCode OpCode {
                get {
                    return this.opCode;
                }
            }

            public int OperandSize {
                get {
                    return this.operandSize;
                }
            }

            /// <summary>
            /// The operand's value capped at 4 byte length.
            /// The length limit affects only the switch opcode: only the number of switch cases is captured, the
            /// jump targets are omitted.
            /// </summary>
            public int OperandValue {
                get {
                    return this.operandValue;
                }
            }

            public int TotalSize {
                get {
                    if (this.OperandSize == -1) {
                        return -1;
                    }
                    return this.opCode.Size + this.operandSize;
                }
            }
        }
        
        /// <summary>
        /// All currently defined two-byte opcodes start with <c>0xfe</c> as first byte.
        /// See also list of opcodes: https://learn.microsoft.com/en-us/dotnet/api/system.reflection.emit.opcodes?view=netframework-4.8.1
        /// </summary>
        private const byte twoByteOpCodeMarker = 0xfe;
        
        /// <summary>
        /// Internal lookup table for single byte op codes. 
        /// </summary>
        private static readonly OpCode?[] oneByteOpCodeLut = new OpCode?[byte.MaxValue + 1];
        
        /// <summary>
        /// Internal lookup table for two byte op codes, indexed by second byte (first byte always 0xfe).
        /// </summary>
        private static readonly OpCode?[] twoByteOpCodeLutBySecondByte = new OpCode?[byte.MaxValue + 1];

        /// <summary>
        /// Instead of hard coding the LUT, read all defined opcodes using reflection (public member only!) and 
        /// build the LUT dynamically
        /// </summary>
        static ILOpcodeLut() {
            foreach (var field in typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static)) {
                if (field.FieldType != typeof(OpCode)) {
                    continue;
                }
                
                var opCode = (OpCode)field.GetValue(null);
                var opCodeValueUnsigned = unchecked((ushort)opCode.Value);

                if (opCode.Size == 1) {
                    Trace.Assert(opCodeValueUnsigned <= byte.MaxValue, "OpCode value exceeds size limit");
                    oneByteOpCodeLut[opCodeValueUnsigned] = opCode;
                } else if (opCode.Size == 2) {
                    Trace.Assert((opCodeValueUnsigned >> 8) == twoByteOpCodeMarker, "Two-Byte OpCode does not start with marker");
                    twoByteOpCodeLutBySecondByte[opCodeValueUnsigned & 0xff] = opCode;
                } else {
                    Trace.Assert(false, "Unexpected OpCode size");
                }
            }
        }
        
        /// <summary>
        /// Reads the OpCode at offset from given IL code.
        /// </summary>
        /// <param name="il">IL code</param>
        /// <param name="position">where to read the opcode</param>
        /// <returns>Information about the opcode and its operand</returns>
        /// <exception cref="IndexOutOfRangeException"><c>il.Count &lt;= position</c></exception>
        /// <exception cref="InvalidDataException">Truncated IL / too few data</exception>
        /// <exception cref="NotSupportedException">Failed to decode: unknown or invalid opcode or operand type</exception>
        public static OpCodeInfo ReadOpcode(IReadOnlyList<byte> il, int position) {
            if (il.Count <= position) {
                throw new IndexOutOfRangeException("il.Count <= position");
            }

            OpCode? maybeOpcode;
            var firstByte = il[position];
            var isTwoByteOpCode = firstByte == twoByteOpCodeMarker; 

            if (!isTwoByteOpCode) {
                maybeOpcode = oneByteOpCodeLut[firstByte];
            } else if (il.Count <= position + 1) {
                throw new InvalidDataException("two byte opcode at il[position], but `ilCount <= position + 1`");
            } else {
                maybeOpcode = twoByteOpCodeLutBySecondByte[il[position + 1]];
            }

            if (maybeOpcode == null) {
                throw new NotSupportedException(string.Format("Invalid or not supported opcode: 0x{0}",
                    isTwoByteOpCode ? (twoByteOpCodeMarker << 8) | il[position + 1] : firstByte));
            }

            var operandSize = GetOperandSize(il, maybeOpcode.Value, position);
            var operandValue = GetOperandValue(il, maybeOpcode.Value, position, operandSize);
            return new OpCodeInfo(maybeOpcode.Value, operandSize, operandValue);
        }

        /// <summary>
        /// Get well-known and constant operand size or <c>-1</c> if operand size is dynamic / depends on context.
        /// All opcodes except <c>Switch</c> have well-known and constant operand size:
        /// Description of operand sizes:
        /// https://learn.microsoft.com/da-dk/dotNet/API/system.reflection.emit.operandtype?view=netframework-4.8.1
        /// Description of switch opcode:
        /// https://learn.microsoft.com/da-dk/dotnet/api/system.reflection.emit.opcodes.switch?view=netframework-4.8.1#remarks
        /// </summary>
        /// <exception cref="NotSupportedException">Unknown/unsupported OperandType (wrt. .Net Framework v4.8)</exception>
        // well known  https://learn.microsoft.com/en-us/dotnet/api/system.reflection.emit.opcodes.switch
        public static int GetConstOperandSize(OperandType operandType) {
            switch (operandType) {
                case OperandType.InlineNone:
                case OperandType.InlinePhi:
                    return 0;
                
                case OperandType.ShortInlineBrTarget:
                case OperandType.ShortInlineI:
                case OperandType.ShortInlineVar:
                    return sizeof(byte);
                
                case OperandType.InlineVar:
                    return sizeof(ushort);
                
                case OperandType.InlineBrTarget:
                case OperandType.InlineField:
                case OperandType.InlineI:
                case OperandType.InlineMethod:
                case OperandType.InlineSig:
                case OperandType.InlineString:
                case OperandType.InlineTok:
                case OperandType.InlineType:
                case OperandType.ShortInlineR:
                    return sizeof(int);
                
                case OperandType.InlineI8:
                case OperandType.InlineR:
                    return sizeof(long);
                
                case OperandType.InlineSwitch:
                    return -1;
                
                default:
                    throw new NotSupportedException("Unsupported IL operand type: " + operandType);
            }
        }

        private static int GetOperandSize(IReadOnlyList<byte> il, OpCode opCode, int opCodePosition) {
            var operandSize = GetConstOperandSize(opCode.OperandType);
            if (operandSize >= 0) {
                return operandSize;
            }

            // other .Net Framework 4.8 opcodes have constant size operands
            if (opCode.OperandType != OperandType.InlineSwitch) {
                throw new NotSupportedException("Unsupported IL operand type with dynamic size: " + opCode.OperandType);
            }
                
            // https://learn.microsoft.com/en-us/dotnet/api/system.reflection.emit.opcodes.switch
            // Switch opcode followed by: N (32Bit) + N * (32Bit Token)
            if (il.Count <= opCodePosition + opCode.Size + sizeof(uint)) {
                throw new InvalidDataException("Too few IL data: incomplete switch target list");
            }
                
            // IL is little endian
            var switchTokenCount = 
                il[opCodePosition + opCode.Size + 0]
                | il[opCodePosition + opCode.Size + 1] << 8
                | il[opCodePosition + opCode.Size + 2] << 16
                | il[opCodePosition + opCode.Size + 3] << 24;
                    
            return sizeof(uint) + switchTokenCount * sizeof(uint);
        }

        private static int GetOperandValue(IReadOnlyList<byte> il, OpCode opCode, int opCodePosition, int operandSize) {
            if (operandSize == 0) {
                return 0;
            }
            
            var opCodeSize = opCode.Size;
            if (il.Count <= opCodePosition + opCodeSize + operandSize) {
                throw new ArgumentException("IL underflow", "il");
            }

            var operand = 0;

            // IL is little-endian
            for (var operandByteIdx = 0; operandByteIdx < operandSize && operandByteIdx < 4; operandByteIdx++) {
                operand |= il[opCodePosition + opCodeSize + operandByteIdx] << 8 * operandByteIdx;
            }
                
            return operand;
        }
    }
}