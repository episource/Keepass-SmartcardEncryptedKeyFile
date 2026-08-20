using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq.Expressions;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

using EpiSource.KeePass.Ekf.Crypto.Exceptions;

namespace EpiSource.KeePass.Ekf.Util {
    
    public static class PinvokeUtil {
        
        public const string PinvokeDataKey = "PInvoke";
        
        public sealed class PinvokeResult<T> {

            private T result;
            private int win32ErrorCode;
            public PinvokeResult(T result, int win32ErrorCode) {
                this.result = result;
                this.win32ErrorCode = win32ErrorCode;
            }

            public T Result { get { return this.result; } }
            public int Win32ErrorCode { get { return this.win32ErrorCode; } }
            
        }

        public struct PinvokeDescription {
            public PinvokeDescription(string description, MethodInfo method) {
                this.description = description;
                this.method = method;
            }
            
            private readonly string description;
            private readonly MethodInfo method;

            public string Description {
                get {
                    return this.description;
                }
            }

            public MethodInfo Method {
                get {
                    return this.method;
                }
            }
        }
        
        [DebuggerStepThrough]
        public static bool DoPinvokeWithException(this Func<bool> pinvokeFunc, Func<PinvokeResult<bool>, Exception> exceptionFactory = null,
                [CallerMemberName] string memberName = null, [CallerFilePath] string sourceFilePath = null, [CallerLineNumber] int sourceLineNumber = 0) {
            return DoPinvokeDetailedWithException(pinvokeFunc, x => x.Result, exceptionFactory, memberName, sourceFilePath, sourceLineNumber).Result;
        }
        
        [DebuggerStepThrough]
        public static T DoPinvokeWithException<T>(this Func<T> pinvokeFunc, Func<PinvokeResult<T>, bool> isGoodPredicate, Func<PinvokeResult<T>, Exception> exceptionFactory = null,
                [CallerMemberName] string memberName = null, [CallerFilePath] string sourceFilePath = null, [CallerLineNumber] int sourceLineNumber = 0) {
            return DoPinvokeDetailedWithException(pinvokeFunc, isGoodPredicate, exceptionFactory, memberName, sourceFilePath, sourceLineNumber).Result;
        }
        
        [DebuggerStepThrough]
        public static PinvokeResult<T> DoPinvokeDetailedWithException<T>(this Func<T> pinvokeFunc, Func<PinvokeResult<T>, bool> isGoodPredicate, Func<PinvokeResult<T>, Exception> exceptionFactory = null,
                [CallerMemberName] string memberName = null, [CallerFilePath] string sourceFilePath = null, [CallerLineNumber] int sourceLineNumber = 0) {
            var result = pinvokeFunc();
            var lastErr = Marshal.GetLastWin32Error();
            var combinedResult = new PinvokeResult<T>(result, lastErr);
            
            if (isGoodPredicate(combinedResult)) return combinedResult;
            
            // decompile PInvoke invocation in case of error to find out call target
            // note: making `pinvokeFunc` an Expression would solve this too without IL-fiddling, but affects every invocation (not just error case)
            var pinvokeMethod = DescribePInvokeInvocation(pinvokeFunc);
            var ex = exceptionFactory != null ? exceptionFactory.Invoke(combinedResult) : new PinvokeException(lastErr, pinvokeMethod);
            ex.SetPinvokeData(pinvokeMethod);
            ex.SetLastWin32ErrorData(lastErr, pinvokeMethod);
            
            // unblocker/remoting: remote stacktrace lost, capture some relevant information explicitly
            ex.SetCallerData(memberName, sourceFilePath, sourceLineNumber);
            
            throw ex;
        }

        /// <summary>
        /// Finds the P/Invoke method directly invoked by the specified delegate.
        ///
        /// Supported cases:
        /// 1. The delegate directly references a P/Invoke method.
        /// 2. The delegate references a managed method/lambda whose IL contains
        ///    exactly one direct "call" of a P/Invoke method.
        ///
        /// For the second case this method skims through the method/lambda's IL code searching for relevant CALL opcodes.
        /// </summary>
        /// <exception cref="NotSupportedException">Unsupported (wrt. .Net Framework 4.8) IL found</exception>
        /// <exception cref="InvalidDataException">Malformed IL data</exception>
        /// <exception cref="InvalidOperationException">Multiple P/Invoke methods are invoked</exception>
        public static MethodInfo FindDirectPInvokeInvocation(Delegate del) {
            if (del == null) {
                throw new ArgumentNullException("del");
            }

            var method = del.Method;

            // Delegate directly references a PInvoke method
            if (method.IsPInvoke()) {
                return method;
            }

            // Decompile delegate's IL to find unique PInvoke call operation
            var body = method.GetMethodBody();
            if (body == null) {
                throw new NotSupportedException("Method referenced by delegate has no IL (abstract or runtime/internal call");
            }
            var il = body.GetILAsByteArray();

            MethodInfo pInvokeMethod = null;
            var position = 0;

            while (position < il.Length) {
                var opCodeInfo = ILOpcodeLut.ReadOpcode(il, position);

                if (opCodeInfo.OpCode == OpCodes.Call) {
                    var token = opCodeInfo.OperandValue;

                    MethodInfo calledMethod = null;
                    try {
                        calledMethod = method.Module.ResolveMethod(token) as MethodInfo;
                    } catch (ArgumentException e) {
                        throw new InvalidDataException("Invalid IL method token", e);
                    }

                    if (calledMethod != null && calledMethod.IsPInvoke()) {
                        // If the delegate calls more than one different P/Invoke method: give up and throw
                        if (pInvokeMethod != null && pInvokeMethod != calledMethod) {
                            throw new InvalidOperationException("Multiple P/Invoke calls");
                        }

                        pInvokeMethod = calledMethod;
                    }
                }

                position += opCodeInfo.TotalSize;
            }

            return pInvokeMethod;
        }

        /// <summary>
        /// Return description of P/Invoke target or error message if no target found. Never throws.
        /// Method property of result maybe null.
        /// </summary>
        public static PinvokeDescription DescribePInvokeInvocation(Delegate del) {
            try {
                var pinvokeMethod = FindDirectPInvokeInvocation(del);
                if (pinvokeMethod == null) {
                    return new PinvokeDescription("<failed to find P/Invoke target: missing>", null);
                }
                
                var dllImport = GetDllImportAttribute(pinvokeMethod);

                var sb = new StringBuilder();
                sb.Append(dllImport != null && dllImport.Value != null ? dllImport.Value : "<unknown dll>");
                sb.Append(":");
                sb.Append(dllImport != null && dllImport.EntryPoint != null ? dllImport.EntryPoint : pinvokeMethod.Name);
                return new PinvokeDescription(sb.ToString(), pinvokeMethod);
            } catch (Exception e) {
                return new PinvokeDescription("<failed to find P/Invoke target: " + e.Message + ">", null);
            }
        }

        public static string DescribeLastWin32Error(int lastWin32Error, PinvokeDescription pinvoke = default(PinvokeDescription)) {
            return pinvoke.Description == null 
                ? string.Format("{0} (0x{1:X})", new Win32Exception(lastWin32Error).Message, lastWin32Error) 
                : string.Format("{0} (0x{1:X}) @ {2}", new Win32Exception(lastWin32Error).Message, lastWin32Error, pinvoke.Description);
        }
        
        /// <summary>
        /// Evaluates state of <see cref="MethodAttributes.PinvokeImpl"/> flag./>
        /// </summary>
        /// <param name="method">Method info to heck.</param>
        /// <returns><c>true</c> if method info refers to a pinvoke signature, else <c>false</c>.</returns>
        public static bool IsPInvoke(this MethodInfo method) {
            return (method.Attributes & MethodAttributes.PinvokeImpl) != 0;
        }
        
        public static void SetPinvokeData(this Exception ex, PinvokeDescription pinvokeMethodDescription) {
            if (pinvokeMethodDescription.Method != null) {
                // MethodInfo not serializable -> ToString()!
                var methodString = pinvokeMethodDescription.Method.ToString();
                if (pinvokeMethodDescription.Method.DeclaringType != null) {
                    methodString = methodString.Replace(pinvokeMethodDescription.Method.Name, pinvokeMethodDescription.Method.DeclaringType.FullName + "." + pinvokeMethodDescription.Method.Name);
                }
                ex.Data[PinvokeDataKey] = methodString;
            }
        }
        
        public static DllImportAttribute GetDllImportAttribute(this MethodInfo method) {
            if (!method.IsPInvoke()) {
                throw new ArgumentException("method is not P/Invoke", "method");
            }
            
            return (DllImportAttribute)Attribute.GetCustomAttribute(method, typeof(DllImportAttribute));
        }

        /// <summary>
        /// Explicitly capture caller information: Stack trace is lost when using remoting/unblocker. 
        /// </summary>
        private static void SetCallerData(this Exception ex, string memberName, string sourceFilePath, int sourceLineNumber) {
            if (memberName == null) {
                return;
            }
            
            var sb = new StringBuilder(memberName);

            if (sourceFilePath != null) {
                sb.Append(" in ").Append(sourceFilePath);

                if (sourceLineNumber != 0) {
                    sb.Append(":line ").Append(sourceLineNumber);
                }
            }
            
            ex.Data["Caller"] = sb.ToString();
        }

        private static void SetLastWin32ErrorData(this Exception ex, int lastWin32Error, PinvokeDescription pinvoke = default(PinvokeDescription)) {
            ex.Data["LastWin32Error"] = DescribeLastWin32Error(lastWin32Error, pinvoke);
        }
        
    }
}