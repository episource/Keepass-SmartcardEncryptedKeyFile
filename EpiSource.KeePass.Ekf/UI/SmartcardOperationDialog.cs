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

using EpiSource.KeePass.Ekf.KeyProvider;

using Episource.KeePass.EKF.Resources;

using EpiSource.KeePass.Ekf.UI.Windows;
using EpiSource.KeePass.Ekf.Util;
using EpiSource.Unblocker;
using EpiSource.Unblocker.Hosting;
using EpiSource.Unblocker.Tasks;
using EpiSource.Unblocker.Util;

using KeePass.UI;

namespace EpiSource.KeePass.Ekf.UI {
    public sealed class SmartcardOperationDialog : Form, IGwmWindow {
        
        #region WorkerResult
        
        [Serializable]
        private class WorkerResult<TTarget, TReturn> {

            private readonly LinkedList<Exception> exceptions = new LinkedList<Exception>();
            
            private InvocationResult<TTarget, TReturn> result;

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

            public InvocationResult<TTarget, TReturn> GetResultOrThrow() {
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
            public void SetResult(InvocationResult<TTarget, TReturn> result) {
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
        
        public static readonly TimeSpan UsuallyShortTaskRecommendedDialogDelay = TimeSpan.FromSeconds(1);

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
        
        #region DoCryptoWithMessagePump factory methods

        public static void DoCryptoWithMessagePump(
            Expression<Action<CancellationToken>> cryptoOperation, CancellationToken ct = default(CancellationToken),
            TimeSpan? showDialogDelay = null
        ) {
            DoCryptoAsync(cryptoOperation, ct, showDialogDelay).AwaitWithMessagePump();
        }
        
        public static IMethodInvocationResult<TTarget> DoCryptoWithMessagePump<TTarget>(TTarget target,
            Expression<Action<CancellationToken, TTarget>> cryptoOperation,
            CancellationToken ct = default(CancellationToken), TimeSpan? showDialogDelay = null) {
            return DoCryptoAsync(target, cryptoOperation, ct, showDialogDelay).AwaitWithMessagePump();
        }
        
        public static TReturn DoCryptoWithMessagePump<TReturn>(
            Expression<Func<CancellationToken, TReturn>> cryptoOperation, CancellationToken ct = default(CancellationToken),
            TimeSpan? showDialogDelay = null
        ) {
            return DoCryptoAsync(cryptoOperation, ct, showDialogDelay).AwaitWithMessagePump();
        }
        
        public static IFunctionInvocationResult<TTarget, TReturn> DoCryptoWithMessagePump<TTarget, TReturn>(TTarget target,
            Expression<Func<CancellationToken, TTarget, TReturn>> cryptoOperation,
            CancellationToken ct = default(CancellationToken), TimeSpan? showDialogDelay = null) {
            return DoCryptoAsync(target, cryptoOperation, ct, showDialogDelay).AwaitWithMessagePump();
        }
        
        public static void DoCryptoWithMessagePumpShort(
            Expression<Action<CancellationToken>> cryptoOperation, CancellationToken ct = default(CancellationToken)
        ) {
            DoCryptoAsync(cryptoOperation, ct, UsuallyShortTaskRecommendedDialogDelay).AwaitWithMessagePump();
        }
        
        public static IMethodInvocationResult<TTarget> DoCryptoWithMessagePumpShort<TTarget>(TTarget target,
            Expression<Action<CancellationToken, TTarget>> cryptoOperation,
            CancellationToken ct = default(CancellationToken)) {
            return DoCryptoAsync(target, cryptoOperation, ct, UsuallyShortTaskRecommendedDialogDelay).AwaitWithMessagePump();
        }
        
        public static TReturn DoCryptoWithMessagePumpShort<TReturn>(
            Expression<Func<CancellationToken, TReturn>> cryptoOperation, CancellationToken ct = default(CancellationToken)
        ) {
            return DoCryptoAsync(cryptoOperation, ct, UsuallyShortTaskRecommendedDialogDelay).AwaitWithMessagePump();
        }
        
        public static IFunctionInvocationResult<TTarget, TReturn> DoCryptoWithMessagePumpShort<TTarget, TReturn>(TTarget target,
            Expression<Func<CancellationToken, TTarget, TReturn>> cryptoOperation,
            CancellationToken ct = default(CancellationToken)) {
            return DoCryptoAsync(target, cryptoOperation, ct, UsuallyShortTaskRecommendedDialogDelay).AwaitWithMessagePump();
        }
        
        #endregion
        
        #region DoCryptoAsync

        public static async Task DoCryptoAsync(
            Expression<Action<CancellationToken>> cryptoOperation, CancellationToken ct = default(CancellationToken),
            TimeSpan? showDialogDelay = null
        ) {
            await DoCryptoImpl(InvocationRequest.FromExpression(cryptoOperation), ct, showDialogDelay)
                .ConfigureAwait(false);
        }
        
        public static async Task<IMethodInvocationResult<TTarget>> DoCryptoAsync<TTarget>(TTarget target,
            Expression<Action<CancellationToken, TTarget>> cryptoOperation, CancellationToken ct = default(CancellationToken),
            TimeSpan? showDialogDelay = null) 
        {
            return await DoCryptoImpl(InvocationRequest.FromExpression(cryptoOperation, target), ct, showDialogDelay);
        }
        
        public static async Task<TReturn> DoCryptoAsync<TReturn>(
            Expression<Func<CancellationToken, TReturn>> cryptoOperation, CancellationToken ct = default(CancellationToken),
            TimeSpan? showDialogDelay = null
        ) {
            return (await DoCryptoImpl(InvocationRequest.FromExpression(cryptoOperation), ct, showDialogDelay)
                .ConfigureAwait(false)).Result;
        }
        
        public static async Task<IFunctionInvocationResult<TTarget, TReturn>> DoCryptoAsync<TTarget, TReturn>(TTarget target, Expression<Func<CancellationToken, TTarget, TReturn>> cryptoOperation, CancellationToken ct = default(CancellationToken),
            TimeSpan? showDialogDelay = null) {
            return await DoCryptoImpl(InvocationRequest.FromExpression(cryptoOperation, target), ct, showDialogDelay)
                .ConfigureAwait(false);
        }
        
        #endregion DoCryptoAsync
        
        #region DoCrypto Implementation

        private static async Task<InvocationResult<TTarget, TReturn>> DoCryptoImpl<TTarget, TReturn>(
            InvocationRequest<TTarget, TReturn> cryptoOperationRequest, CancellationToken ct, TimeSpan? showDialogDelay
        ) {
            var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            
            // Important: Retrieve active form before creating the SmartcardOperationDialog!
            // => Retrieve reference to Keepass window.
            var activeForm = GlobalWindowManager.TopWindow;
            
            var scOperationDialog = new SmartcardOperationDialog(activeForm, cts);

            if (showDialogDelay.HasValue) {
                // Prevent flicker for very short running tasks: Show dialog only for longer running tasks
                // note: not waiting for this task, but finally blocks ensures the task is cancelled reliably
#pragma warning disable CS4014
                Task.Delay(showDialogDelay.Value, cts.Token)
                    .ContinueWith(t => scOperationDialog.Show(activeForm), cts.Token,
                        TaskContinuationOptions.RunContinuationsAsynchronously, TaskScheduler.FromCurrentSynchronizationContext());
#pragma warning restore CS4014
            } else {
                scOperationDialog.Show(activeForm);
            }

            try {
                Expression<Func<CancellationToken, WorkerResult<TTarget, TReturn>>> desktopBoundInvocation = cct => SetDesktopAndExecute<TTarget, TReturn>(
                    cct, cryptoOperationRequest.ToPortableInvocationRequest(), NativeForms.GetCurrentThreadDesktopName(),
                    GetAndResetRemainingHandles());

                var cryptoTaskHandle = await smartcardWorker.InvokeDetailedAsync(
                    desktopBoundInvocation, cts.Token, TimeSpan.FromMilliseconds(gracefulAbortTimeoutMs),
                    ForcedCancellationMode.CleanupBeforeCancellation);
                
                // Win11: native Pin dialog is shown by separate process "CredentialUIBroker"
                // Win10: native Pin dialog is shown by worker/current process
                using (var cryptoProcessWinEvents = new NativeWinEvents()) {
                    var centerTaskCancellationToken = cts.Token;
                    cryptoProcessWinEvents.ObjectShown += (sender, args) => {
                        Process p;
                        try {
                            p = NativeForms.GetProcessOfWindow(args.EventSource);
                        } catch (Win32Exception e) {
                            return;
                        }

                        if (p.ProcessName != "CredentialUIBroker" && p.Id != cryptoTaskHandle.WorkerProcess.Id) {
                            return;
                        }

                        while (!centerTaskCancellationToken.IsCancellationRequested) {
                            try {
                                // set keepass as owner for smartcard dialogs
                                // => to be shown as dialog, always on top of keepass window
                                NativeForms.SetOwner(args.EventSource, activeForm);
                                break;
                            } catch (InvalidWindowHandleException) {
                                // window already gone!
                                return;
                            } catch (Win32Exception e) {
                                // window likely not ready - try again little later
                                // note: this handler is executed by the UI thread!
                                Application.DoEvents();
                            }
                        }

                        while (!centerTaskCancellationToken.IsCancellationRequested) {
                            var windowRect = NativeForms.GetWindowRectangle(args.EventSource);
                            var maximized = NativeForms.IsWindowMaximized(args.EventSource);
                            
                            // Win 10 security dialog starts "pseudo"-maximized, that is as empty window filling the
                            // whole screen. A little bit later it resizes to its actual bounds and centers at
                            // the primary screen. Moving the window is not effective when done earlier.
                            if (!maximized && windowRect.Size != Screen.PrimaryScreen.WorkingArea.Size) {
                                NativeForms.CenterWindow(args.EventSource, activeForm);
                                break;
                            }
                            
                            // this handler is executed by the UI thread!
                            Application.DoEvents();
                        }
                    };


                    // continueOnCapturedContext: true => finally must run within UI thread!
                    // This is default, but be explicit here!
                    var retVal = await cryptoTaskHandle.PlainResult.AsAwaitable().ConfigureAwait(true);
                    
                    AddRemainingHandles(retVal.RemainingDesktopHandles);
                    
                    return retVal.GetResultOrThrow();
                }
            } finally {
                cts.Cancel();
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
        // TODO: Only effective for Win10 smartcard dialogs - Win11 shows smartcard UI using separate process
        //       (CredentialUIBroker.exe), therefore setting the active desktop for the current process has no
        //       effect on the smartcard UIs shown by the OS. In contrast Win10 uses the current process to show
        //       the UI. 
        private static WorkerResult<TTarget, TReturn> SetDesktopAndExecute<TTarget, TReturn>(
            CancellationToken ct, IPortableInvocationRequest portableRequest, string desktop,
            IEnumerable<IntPtr> desktopHandlesToClose) {

            var remainingHandles = new List<IntPtr>(desktopHandlesToClose);
            var currentDesktopHandle = IntPtr.Zero;

            var result = new WorkerResult<TTarget, TReturn>();

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
                    var request = portableRequest.ToInvocationRequest();
                    var invocationResult = request.Invoke(ct);
                    result.SetResult(new InvocationResult<TTarget, TReturn>((TTarget)request.Target, (TReturn)invocationResult, request.HasReturnParameter));
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
            
            GlobalWindowManager.AddWindow(this, this);

            if (this.Owner != null) {
                this.Owner.Enabled = false;
            }
        }

        protected override void OnFormClosing(FormClosingEventArgs e) {
            base.OnFormClosing(e);
            
            if (this.cts != null) {
                this.cts.Cancel();
            }
        }

        protected override void OnClosed(EventArgs e) {
            base.OnClosed(e);
            
            GlobalWindowManager.RemoveWindow(this);

            if (this.Owner != null) {
                this.Owner.Enabled = true;
            }
        }
        
        #endregion
        
        bool IGwmWindow.CanCloseWithoutDataLoss { get { return true; } }

    }
}