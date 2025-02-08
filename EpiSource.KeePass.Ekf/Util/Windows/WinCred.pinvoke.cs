using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

using EpiSource.KeePass.Ekf.Util;

using Microsoft.Win32.SafeHandles;

namespace EpiSource.KeePass.Ekf.Util.Windows {
    public partial class WinCred {
        
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredDeleteW(string target, CredType type, int flagsMustBeZero);
        
        [DllImport("advapi32.dll", SetLastError = false)]
        private static extern void CredFree(IntPtr credential);
        
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredReadW(string target, CredType type, int reserved, out CredentialHandle credential);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredWriteW(ref NativeCredential credential, int flagsMustBeZero);

        private sealed class CredentialHandle : SafeHandleZeroOrMinusOneIsInvalid {
            public CredentialHandle() : base(true) { }

            protected override bool ReleaseHandle() {
                Marshal.PtrToStructure<NativeCredential>(this.handle).ClearCredentialBlob();
                
                CredFree(this.handle);
                return true;
            }

            public GenericCredential GetGenericCredential() {
                if (this.IsClosed || this.IsInvalid) {
                    throw new InvalidOperationException();
                }
                return Marshal.PtrToStructure<NativeCredential>(this.handle).ToGenericCredential();
            }
        }

        private sealed class BytePtrHandle : HGlobalHandle {
            
            public BytePtrHandle() : base(false) {
            }

            public BytePtrHandle(PortableProtectedBinary protectedBinary) : base(protectedBinary.Length) {
                var managedCredentialBlob = protectedBinary.ReadUnprotected();
                Marshal.Copy(managedCredentialBlob, 0, this.handle, protectedBinary.Length);
                Array.Clear(managedCredentialBlob, 0, managedCredentialBlob.Length);
            }
            
            protected override bool ReleaseHandle() {
                // not owned on native->managed transition
                // => ReleaseHandle only invoked for managed HGlobal Allocations
                
                var zero = new byte[this.Size];
                Marshal.Copy(zero, 0, this.handle, this.Size);
                
                return base.ReleaseHandle();
            }
            
        }
        
        /// https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentiala
        private enum CredType {
            GENERIC = 1,
            DOMAIN_PASSWORD = 2,
            DOMAIN_CERTIFICATE = 3,
            DOMAIN_VISIBLE_PASSWORD = 4,
            GENERIC_CERTIFICATE = 5,
            DOMAIN_EXTENDED = 6
        }

        [Flags]
        private enum CredFlags {
            NONE = 0,
            PROMPT_NOW = 2,
            USERNAME_TARGET = 4
        }

        private enum WinCredErrorCode {
            ERROR_INVALID_PARAMETER = 0x57,
            ERROR_INVALID_FLAGS = 0x3ec,
            ERROR_NOT_FOUND = 0x490,
            ERROR_NO_SUCH_LOGON_SESSION = 0x520,
            ERROR_BAD_USERNAME = 0x89a,
            SCARD_E_NO_SMARTCARD = unchecked((int)0x8010000C),
            SCARD_E_NO_READERS_AVAILABLE = unchecked((int)0x8010002E),
            SCARD_W_REMOVED_CARD = unchecked((int)0x80100069),
            SCARD_W_WRONG_CHV = unchecked((int)0x8010006B)
            
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct NativeCredential {
            public CredFlags Flags;
            public CredType Type;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string TargetName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string Comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
            public int CredentialBlobSize;
            public IntPtr CredentialBlob;
            public CredentialPersistence Persist;
            public int AttributeCount;
            public IntPtr Attributes;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string TargetAlias;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string UserName;

            public void ClearCredentialBlob() {
                var zero = new byte[this.CredentialBlobSize];
                Marshal.Copy(zero, 0, this.CredentialBlob, zero.Length);
            }

            public GenericCredential ToGenericCredential() {
                if (this.Type != CredType.GENERIC) {
                    return null;
                }
                
                var managedCredentialBlob = new byte[this.CredentialBlobSize];
                Marshal.Copy(this.CredentialBlob, managedCredentialBlob, 0, managedCredentialBlob.Length);

                var managedAttributes = new Dictionary<string, IList<byte>>(this.AttributeCount);
                for (var i = 0; i < this.AttributeCount; ++i) {
                    var nativeAttribute = Marshal.PtrToStructure<NativeCredentialAttribute>(this.Attributes + i * Marshal.SizeOf<NativeCredentialAttribute>());
                    
                    var managedValue = new byte[nativeAttribute.ValueSize];
                    Marshal.Copy(nativeAttribute.Value, managedValue, 0, nativeAttribute.ValueSize);
                    
                    managedAttributes.Add(nativeAttribute.Keyword, managedValue);
                }
                
                return new GenericCredential(this.TargetName, PortableProtectedBinary.Move(managedCredentialBlob), this.UserName, this.TargetAlias, this.Comment, managedAttributes);
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct NativeCredentialAttribute {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string Keyword;
            private int FlagsMustBeZero;
            public int ValueSize;
            public IntPtr Value;
        }

    }
}