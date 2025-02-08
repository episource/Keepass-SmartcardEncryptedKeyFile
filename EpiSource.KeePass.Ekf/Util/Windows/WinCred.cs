using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

using EpiSource.KeePass.Ekf.Util;

namespace EpiSource.KeePass.Ekf.Util.Windows {
    public partial class WinCred {
        public static bool DeleteGenericCredential(string targetName) {
            return PinvokeUtil.DoPinvokeWithException(() => CredDeleteW(targetName, CredType.GENERIC, 0),
                r => r.Result || r.Win32ErrorCode == (int)WinCredErrorCode.ERROR_NOT_FOUND);
        }
        
        public static GenericCredential ReadGenericCredential(string targetName) {
            CredentialHandle credHandle = null;
                PinvokeUtil.DoPinvokeWithException(() => CredReadW(targetName, CredType.GENERIC, 0, out credHandle),
                    r => r.Win32ErrorCode == (int)WinCredErrorCode.ERROR_NOT_FOUND 
                        ? new KeyNotFoundException(targetName + " (GENERIC)") : null);
                
            using (credHandle) {
                return credHandle == null ? null : credHandle.GetGenericCredential();
            }
        }

        public static bool TryReadGenericCredential(string targetName, out GenericCredential cred) {
            CredentialHandle credHandle = null;
            var success = CredReadW(targetName, CredType.GENERIC, 0, out credHandle);
            
            using (credHandle) {
                if (!success) {
                    cred = null;
                    return false;
                }

                cred = credHandle.GetGenericCredential();
                return true;
            }
        }

        public static void WriteGenericCredential(GenericCredential credential, CredentialPersistence persistence=CredentialPersistence.LocalMachine) {
            var attributeDataOffset = credential.Attributes.Count * Marshal.SizeOf<NativeCredentialAttribute>();
            var attributeStorageSizeBytes = 
                attributeDataOffset + credential.Attributes.Sum(attr => attr.Value.Count);

            using (var credentialBlobHandle = new BytePtrHandle(credential.CredentialBlob))
            using (var attributesMemoryHandle = new HGlobalHandle(attributeStorageSizeBytes))
            using (var marshaledStructureHandle = new MarshaledStructureHandleCollection()) {
                credential.Attributes.Aggregate(0, (idx, attr) => {
                    var managedValue = attr.Value.ToArray();
                    var nativeValuePtr = attributesMemoryHandle.DangerousGetHandle() + attributeDataOffset;
                    Marshal.Copy(managedValue, 0, nativeValuePtr, managedValue.Length);
                    attributeDataOffset += managedValue.Length;

                    var nativeAttr = new NativeCredentialAttribute() {
                        Keyword = attr.Key,
                        ValueSize = managedValue.Length,
                        Value = nativeValuePtr
                    };

                    var nativeStructurePtr = attributesMemoryHandle.DangerousGetHandle() + idx * Marshal.SizeOf<NativeCredentialAttribute>();
                    Marshal.StructureToPtr(nativeAttr, nativeStructurePtr, false);
                    marshaledStructureHandle.AddStructure<NativeCredentialAttribute>(nativeStructurePtr);
                    
                    return idx + 1;
                });
                
                var nativeCred = new NativeCredential() {
                    Flags = CredFlags.NONE,
                    Type = CredType.GENERIC,
                    TargetName = credential.TargetName,
                    Comment = credential.Comment,
                    TargetAlias = credential.TargetAlias,
                    Persist = persistence,
                    CredentialBlobSize = credentialBlobHandle.Size,
                    CredentialBlob = credentialBlobHandle.DangerousGetHandle(),
                    UserName = credential.UserName,
                    AttributeCount = credential.Attributes.Count,
                    Attributes = attributesMemoryHandle.DangerousGetHandle()
                };
                
                PinvokeUtil.DoPinvokeWithException(() => CredWriteW(ref nativeCred, 0));
            }
        }
    }
}