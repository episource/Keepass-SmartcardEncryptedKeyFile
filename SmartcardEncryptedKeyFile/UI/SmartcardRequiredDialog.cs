using System;
using System.Drawing;
using System.Linq.Expressions;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Windows.Forms.VisualStyles;

using episource.unblocker;
using episource.unblocker.hosting;

using Episource.KeePass.EKF.UI.Windows;
using Episource.KeePass.EKF.Util;

namespace Episource.KeePass.EKF.UI {
    public sealed class SmartcardRequiredDialog : Form {
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
            await DoCryptoImpl(ct,
                (u, realCt, pRef) =>
                    u.InvokeAsync(cryptoOperation, realCt, forcedCancellationMode: forcedCancellationMode,
                        workerProcessRef: pRef).AddDefaultResult<object>()
            ).ConfigureAwait(false);
        }
        
        public static async Task<T> DoCryptoAsync<T>(
            Expression<Func<CancellationToken, T>> cryptoOperation, CancellationToken ct = default(CancellationToken),
            ForcedCancellationMode forcedCancellationMode = ForcedCancellationMode.KillImmediately
        ) {
            return await DoCryptoImpl(ct,
                (u, realCt, pRef) =>
                    u.InvokeAsync(cryptoOperation, realCt, forcedCancellationMode: forcedCancellationMode,
                        workerProcessRef: pRef)
            ).ConfigureAwait(false);
        }

        private static async Task<T> DoCryptoImpl<T>(
            CancellationToken ct, Func<Unblocker, CancellationToken, WorkerProcessRef, Task<T>> cryptoInvocation
        ) {
            var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var pRef = new WorkerProcessRef();

            var activeForm = NativeForms.GetActiveWindow();

            var scRequiredDialog = new SmartcardRequiredDialog(activeForm, cts);
            scRequiredDialog.Show(activeForm);

            try {
                var cryptoTask = cryptoInvocation(UnblockerSingleton.DefaultInstance, cts.Token, pRef);
                using (var cryptoProcessWinEvents = new NativeWinEvents(pRef.WorkerProcess)) {
                    cryptoProcessWinEvents.ForegroundChanged +=
                        (sender, args) => NativeForms.SetOwner(args.EventSource, activeForm);

                    return await cryptoTask;
                }
            } finally {
                scRequiredDialog.Close();
            }
        }
        
        #endregion
    }
}