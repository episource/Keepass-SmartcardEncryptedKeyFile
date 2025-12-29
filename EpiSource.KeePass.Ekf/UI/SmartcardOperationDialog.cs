using System;
using System.Drawing;
using System.Linq.Expressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

using Episource.KeePass.EKF.Resources;

using EpiSource.KeePass.Ekf.Util;
using EpiSource.Unblocker;
using EpiSource.Unblocker.Hosting;

using KeePass.UI;

namespace EpiSource.KeePass.Ekf.UI {
    public sealed class SmartcardOperationDialog : Form, IGwmWindow {
        
        public static readonly TimeSpan UsuallyShortTaskRecommendedDialogDelay = TimeSpan.FromSeconds(1);

        private const int gracefulAbortTimeoutMs = 100;
        
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

        private static async Task<IFunctionInvocationResult<TTarget, TReturn>> DoCryptoImpl<TTarget, TReturn>(
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
                // continueOnCapturedContext: true => finally must run within UI thread!
                // This is default, but be explicit here!
                return await smartcardWorker.InvokeMutableAsync(
                        cryptoOperationRequest, cts.Token, TimeSpan.FromMilliseconds(gracefulAbortTimeoutMs),
                        ForcedCancellationMode.CleanupBeforeCancellation)
                                .ConfigureAwait(true);
            } finally {
                cts.Cancel();
                scOperationDialog.Close();
            }
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