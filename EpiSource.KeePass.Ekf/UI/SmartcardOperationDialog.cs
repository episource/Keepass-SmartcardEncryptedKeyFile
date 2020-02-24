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

using Episource.KeePass.EKF.Resources;

using EpiSource.KeePass.Ekf.UI.Windows;
using EpiSource.KeePass.Ekf.Util;
using EpiSource.Unblocker;
using EpiSource.Unblocker.Hosting;

namespace EpiSource.KeePass.Ekf.UI {
    public sealed class SmartcardOperationDialog : Form {
        
        #region WorkerResult
        
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
        
        #endregion

        private const int gracefulAbortTimeoutMs = 100;
        private const string defaultDesktopName = "Default";
        
        // A dedicated worker process pool is used:
        // - smartcard operations involve native code without support for cancellation; hence the process needs
        // to be killed to cancel
        // - Some smartcards require the pin to be entered just once. This is bound to the requesting process. Hence
        // the standby timeout is chosen quite long.
        // - Worker limit is set to one, such that smartcard operations are not done in parallel.
        // - Unblocker creates the first worker process on first invocation only, therefore there's no need for
        // explicit lazy initialization
        // ReSharper disable once RedundantArgumentDefaultValue
        private static readonly UnblockerHost smartcardWorker = new UnblockerHost(
            standbyDelay: TimeSpan.FromSeconds(500000), maxWorkers: 1, debug: DebugMode.None);

        // set via ReplaceRemainingHandles only
        private static volatile ISet<IntPtr> remainingDesktopHandles = new HashSet<IntPtr>();
        
        private readonly TableLayoutPanel layout = new TableLayoutPanel();
        private readonly CancellationTokenSource cts;

        private SmartcardOperationDialog(Form owner, CancellationTokenSource cts) {
            this.cts = cts;
            this.InitializeUI();

            if (owner != null) {
                this.Owner = owner;
            }
        }
        
        #region DoCrypto factory methods

        public static void DoCryptoWithMessagePump(
            Expression<Action<CancellationToken>> cryptoOperation, CancellationToken ct = default(CancellationToken)
        ) {
            DoCryptoAsync(cryptoOperation, ct).AwaitWithMessagePump();
        }
        
        public static T DoCryptoWithMessagePump<T>(
            Expression<Func<CancellationToken, T>> cryptoOperation, CancellationToken ct = default(CancellationToken)
        ) {
            return DoCryptoAsync(cryptoOperation, ct).AwaitWithMessagePump();
        }

        public static async Task DoCryptoAsync(
            Expression<Action<CancellationToken>> cryptoOperation, CancellationToken ct = default(CancellationToken)
        ) {
            await DoCryptoImpl(InvocationRequest.FromExpression(cryptoOperation), ct)
                .ConfigureAwait(false);
        }
        
        public static async Task<T> DoCryptoAsync<T>(
            Expression<Func<CancellationToken, T>> cryptoOperation, CancellationToken ct = default(CancellationToken)
        ) {
            return (T) await DoCryptoImpl(InvocationRequest.FromExpression(cryptoOperation), ct)
                .ConfigureAwait(false);
        }

        private static async Task<object> DoCryptoImpl(
            InvocationRequest cryptoOperationRequest, CancellationToken ct
        ) {
            var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var pRef = new WorkerProcessRef();

            var activeForm = NativeForms.GetActiveWindow();
            
            var scOperationDialog = new SmartcardOperationDialog(activeForm, cts);
            scOperationDialog.Show(activeForm);

            try {
                Expression<Func<CancellationToken, WorkerResult>> desktopBoundInvocation = cct => SetDesktopAndExecute(
                    cct, cryptoOperationRequest.ToPortableInvocationRequest(), NativeForms.GetCurrentThreadDesktopName(),
                    GetAndResetRemainingHandles());
                
                var cryptoTask = smartcardWorker.InvokeAsync(
                    desktopBoundInvocation, cts.Token, TimeSpan.FromMilliseconds(gracefulAbortTimeoutMs),
                    ForcedCancellationMode.CleanupBeforeCancellation, workerProcessRef: pRef);
                using (var cryptoProcessWinEvents = new NativeWinEvents(pRef.WorkerProcess)) {
                    var uiCentered = false;
                    var knownWindows = new HashSet<IntPtr>();
                    cryptoProcessWinEvents.ObjectShown +=
                        (sender, args) => {
                            if (knownWindows.Add(args.EventSource)) {
                                NativeForms.SetOwner(args.EventSource, activeForm);
                            }

                            if (!uiCentered) {
                                var windowRect = NativeForms.GetWindowRectangle(args.EventSource);
                                var maximized = NativeForms.IsWindowMaximized(args.EventSource);
                                
                                // Win 10 security dialog starts "pseudo"-maximized, that is as empty window filling the
                                // whole screen. A little bit later it resizes to its actual bounds and centers at
                                // the primary screen. Moving the window is not effective when done earlier.
                                if (!maximized && windowRect.Size != Screen.PrimaryScreen.WorkingArea.Size) {
                                    NativeForms.CenterWindow(args.EventSource, activeForm);
                                    uiCentered = true;
                                }
                            }
                        };
                    
                    // continueOnCapturedContext: true => finally must run within UI thread!
                    var retVal = await cryptoTask.ConfigureAwait(true);
                    AddRemainingHandles(retVal.RemainingDesktopHandles);
                    return retVal.GetResultOrThrow();
                }
            } finally {
                scOperationDialog.Close();
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
                
                // ReSharper disable once PossibleMultipleEnumeration
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
                if (desktop != null && desktop != defaultDesktopName ) {
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
                    ct.Register(() => Process.GetCurrentProcess().CloseMainWindow());
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

        #region UI
        
        private void InitializeUI() {
            this.SuspendLayout();

            this.StartPosition = FormStartPosition.CenterParent;

            this.AutoSize = true;
            this.Size = new Size(0, 0);
            this.AutoScaleMode = UIConstants.AutoScaleMode;
            this.AutoScaleDimensions = UIConstants.AutoScaleDimensions;
            this.Padding = new Padding(12);

            this.Text = Strings.SmartcardOperationDialog_DialogTitle;

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
                Text = Strings.SmartcardOperationDialog_DialogHeading,
                AutoSize = true,
            };
            titleText.Font = new Font(titleText.Font, FontStyle.Bold);
            this.layout.Controls.Add(titleText, 1, 0);

            var msgText = new Label {
                MaximumSize = maxLabelSize,
                Text = Strings.SmartcardOperationDialog_DialogText,
                AutoSize = true
            };
            this.layout.Controls.Add(msgText, 1, 1);

            var btnAbort = new Button {
                Text = Strings.AnyUI_ButtonAbort,
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

        protected override void OnLoad(EventArgs e) {
            base.OnLoad(e);

            if (this.Owner != null) {
                this.CenterToParent();
            }
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

    }
}