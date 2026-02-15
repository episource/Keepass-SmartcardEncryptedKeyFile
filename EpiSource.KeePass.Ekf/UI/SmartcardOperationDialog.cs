using System;
using System.Diagnostics;
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
    public partial class SmartcardOperationDialogFactory {
        private sealed class SmartcardOperationDialog : Form, IGwmWindow {

            private readonly TableLayoutPanel layout = new TableLayoutPanel();
            private readonly CancellationTokenSource cts;

            internal SmartcardOperationDialog(Form owner, CancellationTokenSource cts) {
                this.cts = cts;
                this.InitializeUI();

                if (owner != null) {
                    this.Owner = owner;
                }
            }

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
}