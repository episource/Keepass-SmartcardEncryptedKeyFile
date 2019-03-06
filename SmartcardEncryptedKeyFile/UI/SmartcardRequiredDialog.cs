using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Linq.Expressions;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

using episource.unblocker;
using episource.unblocker.hosting;

using Episource.KeePass.EKF.UI.Windows;
using Episource.KeePass.EKF.Util;

namespace Episource.KeePass.EKF.UI {
    public sealed class SmartcardRequiredDialog : Form {
        
        [Serializable]
        private class WorkerResult {

            private readonly LinkedList<Exception> exceptions = new LinkedList<Exception>();
            
            private object result;
            
            // ReSharper disable once MemberHidesStaticFromOuterClass
            private IEnumerable<IntPtr> remainingDesktopHandles;
            
            public IEnumerable<IntPtr> RemainingDesktopHandles {
                get {
                    if (this.remainingDesktopHandles == null) {
                        throw new InvalidOperationException("remainingDesktopHandles not set");
                    }
                    return this.remainingDesktopHandles;
                }
            }

            public object GetResultOrThrow() {
                if (this.exceptions.Count > 1) {
                    throw new AggregateException("Smartcard operation failed.", this.exceptions);
                } 
                if (this.exceptions.Count == 1) {
                    ExceptionDispatchInfo.Capture(this.exceptions.First()).Throw();
                    throw new InvalidOperationException("This code should be unreachable...");
                }

                return this.result;
            }

            public void AddException(Exception e) {
                this.exceptions.AddLast(e);
            }

            // ReSharper disable once ParameterHidesMember
            public void SetResult(object result) {
                this.result = result;
            }

            // ReSharper disable once ParameterHidesMember
            public void SetRemainingDesktopHandles(IEnumerable<IntPtr> remainingDesktopHandles) {
                if (this.remainingDesktopHandles != null) {
                    throw new InvalidOperationException("remainingDesktopHandles already set");
                }
                
                this.remainingDesktopHandles = remainingDesktopHandles;
            }
            
        }
        
        private const string DefaultDesktopName = "Default";
        
        // A dedicated worker process pool is used:
        // - smartcard operations involve native code without support for cancellation; hence the process needs
        // to be killed to cancel
        // - Some smartcards require the pin to be entered just once. This is bound to the requesting process. Hence
        // the standby timeout is chosen quite long.
        // - Worker limit is set to one, such that smartcard operations are not done in parallel.
        // - Unblocker creates the first worker process on first invocation only, therefore there's no need for
        // explicit lazy initialization
        private static Unblocker smartcardWorker = new Unblocker(
            standbyDelay: TimeSpan.FromSeconds(500000), maxWorkers: 1, debug: DebugMode.None);

        // set via ReplaceRemainingHandles only
        private static volatile ISet<IntPtr> remainingDesktopHandles = new HashSet<IntPtr>();
        
        private readonly TableLayoutPanel layout = new TableLayoutPanel();
        private readonly CancellationTokenSource cts;

        private SmartcardRequiredDialog(Form owner, CancellationTokenSource cts) {
            this.cts = cts;
            this.InitializeUI();

            if (owner != null) {
                this.Owner = owner;
            }
        }

        #region UI
        
        private void InitializeUI() {
            this.SuspendLayout();

            this.AutoSize = true;
            this.Size = new Size(0, 0);
            this.AutoScaleMode = UIConstants.AutoScaleMode;
            this.AutoScaleDimensions = UIConstants.AutoScaleDimensions;
            this.Padding = new Padding(12);

            this.Text = "Smartcard required";

            this.MinimizeBox = false;
            this.MaximizeBox = false;
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.ShowInTaskbar = false;

            this.layout.Top = 0;
            this.layout.Left = 0;
            this.layout.AutoSize = true;
            this.layout.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            this.layout.Dock = DockStyle.Fill;
            this.layout.ColumnCount = 4;
            this.layout.RowCount = 6;
            this.layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            this.layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            this.layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            this.layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            this.layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            this.Controls.Add(this.layout);

            var iconBox = new PictureBox {
                Width = SystemIcons.Information.Width,
                Image = SystemIcons.Information.ToBitmap(),
                Margin = new Padding(0, 0, this.Padding.Right / 2, this.Padding.Bottom / 2)
            };
            this.layout.Controls.Add(iconBox, 0, 0);
            this.layout.SetRowSpan(iconBox, 2);

            var maxLabelSize = new Size(300, 0);
            var titleText = new Label {
                MaximumSize = maxLabelSize,
                Text = "Please insert and unlock your smartcard.",
                AutoSize = true,
            };
            titleText.Font = new Font(titleText.Font, FontStyle.Bold);
            this.layout.Controls.Add(titleText, 1, 0);

            var msgText = new Label {
                MaximumSize = maxLabelSize,
                Text =
                    "Among others, this may require entering a PIN or pressing a button. Details depend on the type of smartcard and reader you are using.",
                AutoSize = true
            };
            this.layout.Controls.Add(msgText, 1, 1);

            var btnAbort = new Button {
                Text = "Abort",
                DialogResult = DialogResult.Abort,
                Height = UIConstants.DefaultButtonHeight,
                Width = UIConstants.DefaultButtonWidth,
                MaximumSize = new Size(UIConstants.DefaultButtonWidth, UIConstants.DefaultButtonHeight),
                Anchor = AnchorStyles.None,
                TabIndex = 1
            };
            btnAbort.Click += (sender, args) => this.cts.Cancel();
            this.layout.Controls.Add(btnAbort, 0, 2);
            this.layout.SetColumnSpan(btnAbort, this.layout.ColumnCount);

            this.ResumeLayout();
        }

        protected override void OnShown(EventArgs e) {
            base.OnShown(e);

            if (this.Owner != null) {
                this.Owner.Enabled = false;
            }
        }

        protected override void OnClosed(EventArgs e) {
            base.OnClosed(e);

            if (this.Owner != null) {
                this.Owner.Enabled = true;
            }
        }
        
        #endregion

        #region DoCrypto factory methods

        public static void DoCryptoWithMessagePump(
            Expression<Action<CancellationToken>> cryptoOperation, CancellationToken ct = default(CancellationToken),
            ForcedCancellationMode forcedCancellationMode = ForcedCancellationMode.KillImmediately
        ) {
            DoCryptoAsync(cryptoOperation, ct, forcedCancellationMode).AwaitWithMessagePump();
        }
        
        public static T DoCryptoWithMessagePump<T>(
            Expression<Func<CancellationToken, T>> cryptoOperation, CancellationToken ct = default(CancellationToken),
            ForcedCancellationMode forcedCancellationMode = ForcedCancellationMode.KillImmediately
        ) {
            return DoCryptoAsync(cryptoOperation, ct, forcedCancellationMode).AwaitWithMessagePump();
        }

        public static async Task DoCryptoAsync(
            Expression<Action<CancellationToken>> cryptoOperation, CancellationToken ct = default(CancellationToken),
            ForcedCancellationMode forcedCancellationMode = ForcedCancellationMode.KillImmediately
        ) {
            await DoCryptoImpl(InvocationRequest.FromExpression(cryptoOperation), ct, forcedCancellationMode)
                .ConfigureAwait(false);
        }
        
        public static async Task<T> DoCryptoAsync<T>(
            Expression<Func<CancellationToken, T>> cryptoOperation, CancellationToken ct = default(CancellationToken),
            ForcedCancellationMode forcedCancellationMode = ForcedCancellationMode.KillImmediately
        ) {
            return (T) await DoCryptoImpl(InvocationRequest.FromExpression(cryptoOperation), ct, forcedCancellationMode)
                .ConfigureAwait(false);
        }

        private static async Task<object> DoCryptoImpl(
            InvocationRequest cryptoOperationRequest, CancellationToken ct,
            ForcedCancellationMode forcedCancellationMode
        ) {
            var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var pRef = new WorkerProcessRef();

            var activeForm = NativeForms.GetActiveWindow();
            
            var scRequiredDialog = new SmartcardRequiredDialog(activeForm, cts);
            scRequiredDialog.Show(activeForm);

            try {
                Expression<Func<CancellationToken, WorkerResult>> desktopBoundInvocation = cct => SetDesktopAndExecute(
                    cct, cryptoOperationRequest.ToPortableInvocationRequest(), NativeForms.GetCurrentThreadDesktopName(),
                    GetAndResetRemainingHandles());
                
                var cryptoTask = smartcardWorker.InvokeAsync(
                    desktopBoundInvocation, cts.Token, forcedCancellationMode: forcedCancellationMode,
                    workerProcessRef: pRef);
                using (var cryptoProcessWinEvents = new NativeWinEvents(pRef.WorkerProcess)) {
                    cryptoProcessWinEvents.ForegroundChanged +=
                        (sender, args) => NativeForms.SetOwner(args.EventSource, activeForm);
                    
                    // continueOnCapturedContext: true => finally must run within UI thread!
                    var retVal = await cryptoTask.ConfigureAwait(true);
                    AddRemainingHandles(retVal.RemainingDesktopHandles);
                    return retVal.GetResultOrThrow();
                }
            } finally {
                scRequiredDialog.Close();
            }
        }

        private static IEnumerable<IntPtr> GetAndResetRemainingHandles() {
            ISet<IntPtr> currentRemainingHandles;
            var nextRemainingHandles = new HashSet<IntPtr>();
            
            do {
                currentRemainingHandles = remainingDesktopHandles;

                // currently this succeeds immediately, as the maxWorker setting effectively serialized things
                // but: be 100% sure in case of future changes
            } while(currentRemainingHandles != Interlocked.CompareExchange(ref remainingDesktopHandles,
                        nextRemainingHandles, currentRemainingHandles));

            return currentRemainingHandles;
        }
        private static void AddRemainingHandles(IEnumerable<IntPtr> newRemainingHandles) {
            ISet<IntPtr> currentRemainingHandles;
            ISet<IntPtr> nextRemainingHandles;
            
            do {
                currentRemainingHandles = remainingDesktopHandles;
                nextRemainingHandles = new HashSet<IntPtr>(currentRemainingHandles);
                foreach (var handle in newRemainingHandles) {
                    nextRemainingHandles.Add(handle);
                }

                // currently this succeeds immediately, as the maxWorker setting effectively serialized things
                // but: be 100% sure in case of future changes
            } while(currentRemainingHandles != Interlocked.CompareExchange(ref remainingDesktopHandles,
                nextRemainingHandles, currentRemainingHandles));
            
        }

        // Switch to "secure" desktop prior to smart card operations: This is needed for any user interaction to
        // be visible if "secure" desktop is used.
        // Note: Some system components, e.g. Win 10 smartcard dialogs, keep running in background for a while after
        // the dialog has ended. This prevents the secure desktop handle to be closed immediately. An attempt to close
        // remaining handles is done with every smartcard operation.
        // As long as desktop handles are not closed, the temporary "secure" desktop created by keepass remains active.
        // Therefore, if immediate closing fails, the temporary desktop is kept alive longer than needed, e.g. until
        // the next smartcard operation. This is tolerated. It doesn't affect user experience, but increases resource
        // consumption.
        // At latest, all desktop handles are released when the worker process shuts down, that is after the chosen
        // standby timeout has passed without user operation.
        private static WorkerResult SetDesktopAndExecute(
            CancellationToken ct, InvocationRequest.PortableInvocationRequest request, string desktop,
            IEnumerable<IntPtr> desktopHandlesToClose) {

            var remainingHandles = new List<IntPtr>(desktopHandlesToClose);
            var currentDesktopHandle = IntPtr.Zero;

            var result = new WorkerResult();

            try {
                if (desktop != null && desktop != DefaultDesktopName ) {
                    currentDesktopHandle = NativeForms.GetCurrentThreadDesktop();
                    var secureDesktopHandle = NativeForms.OpenDesktop(desktop);

                    if (currentDesktopHandle != secureDesktopHandle) {
                        NativeForms.SetCurrentThreadDesktop(secureDesktopHandle);
                        remainingHandles.Add(secureDesktopHandle);
                    } else {
                        NativeForms.CloseDesktop(secureDesktopHandle);
                    }
                }

                try {
                    var invocationResult = request.ToInvocationRequest().Invoke(ct);
                    result.SetResult(invocationResult);
                } catch (Exception e) {
                    result.AddException(e);
                }
            } finally {
                try {
                    Process.GetCurrentProcess().CloseMainWindow();
                } catch { /* try anyway - no need to forward exception */ }

                try {
                    if (currentDesktopHandle != IntPtr.Zero) {
                        NativeForms.SetCurrentThreadDesktop(currentDesktopHandle);
                    }
                } catch (Exception e) {
                    result.AddException(e);
                }

                result.SetRemainingDesktopHandles(remainingHandles.Where(h => {
                    try {
                        NativeForms.CloseDesktop(h);
                        return false;
                    } catch (Win32Exception e) {
                        const int errorBusy =  0x000000AA;
                        const int errorInvalid = 0x00000006;

                        switch (e.NativeErrorCode) {
                            case errorBusy:
                                // try again next time
                                return true;
                            case errorInvalid:
                                // desktop has already been disposed (maybe new worker process)
                                return false;
                            default:
                                result.AddException(e);
                                return true;
                        }
                    } catch (Exception e) {
                        result.AddException(e);
                        return true;
                    }
                }).ToList());
            }

            return result;
        }
                
        #endregion
    }
}