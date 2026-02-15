using System;
using System.Drawing;
using System.Windows.Forms;

using Episource.KeePass.EKF.Resources;

using EpiSource.KeePass.Ekf.Util;

using KeePass.UI;

namespace EpiSource.KeePass.Ekf.UI {
    public partial class PinPromptDialogFactory {
        private sealed partial class PinPromptDialog : Form, IGwmWindow {

            private static readonly PinPromptDialogResult CancelledResult = new PinPromptDialogResult(null, false);

            internal PinPromptDialogResult result = CancelledResult;

            internal PinPromptDialog(Form owner, string description, bool isRetry) {
                if (owner != null) {
                    this.Owner = owner;
                }

                this.InitializeUI(description, isRetry);
            }

            private void InitializeUI(string description, bool isRetry) {
                this.SuspendLayout();

                this.StartPosition = FormStartPosition.CenterParent;

                this.AutoSize = true;
                this.AutoSizeMode = AutoSizeMode.GrowAndShrink;
                this.AutoScaleMode = UIConstants.AutoScaleMode;
                this.AutoScaleDimensions = UIConstants.AutoScaleDimensions;
                this.SizeGripStyle = SizeGripStyle.Hide;

                this.Text = Strings.PinPromptDialog_Title;

                this.MinimizeBox = false;
                this.MaximizeBox = false;
                this.FormBorderStyle = FormBorderStyle.FixedDialog;
                this.ShowInTaskbar = false;

                var mainLayout = new TableLayoutPanel();
                mainLayout.AutoSize = true;
                mainLayout.AutoSizeMode = AutoSizeMode.GrowAndShrink;
                mainLayout.Width = 0;
                mainLayout.Height = 0;
                mainLayout.GrowStyle = TableLayoutPanelGrowStyle.FixedSize;
                mainLayout.Dock = DockStyle.Fill;
                mainLayout.ColumnCount = 5;
                mainLayout.RowCount = 8;
                mainLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 9));
                mainLayout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
                mainLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
                mainLayout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
                mainLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 9));
                mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 60));
                mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 9));
                mainLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
                if (isRetry) {
                    mainLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
                    mainLayout.RowCount += 1;
                }
                mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 9));
                mainLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
                mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 9));
                mainLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
                mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 9));
                this.Controls.Add(mainLayout);


                int currentMainRow = 0;

                var banner = new PictureBox();
                banner.Dock = DockStyle.Fill;
                banner.Padding = new Padding(0);
                banner.Margin = new Padding(0);
                banner.TabStop = false;
                mainLayout.Controls.Add(banner, 0, currentMainRow);
                mainLayout.SetColumnSpan(banner, mainLayout.ColumnCount);


                currentMainRow += 2;

                var lblPin = new Label();
                lblPin.Text = Strings.PinPromptDialog_PinInput;
                lblPin.Width = 32;
                lblPin.Height = 25;
                lblPin.TextAlign = ContentAlignment.MiddleLeft;
                lblPin.Anchor = AnchorStyles.Left | AnchorStyles.Top | AnchorStyles.Bottom;
                mainLayout.Controls.Add(lblPin, 1, currentMainRow);

                var pinInput = new SecureTextBoxEx();
                pinInput.Width = 240;
                pinInput.Height = 20;
                pinInput.Margin = new Padding(this.DefaultMargin.Left, 6, this.DefaultMargin.Right, this.DefaultMargin.Bottom);
                pinInput.Anchor = AnchorStyles.Left | AnchorStyles.Bottom | AnchorStyles.Top | AnchorStyles.Right;
                mainLayout.Controls.Add(pinInput, 2, currentMainRow);

                var cbShowPin = new CheckBox();
                cbShowPin.Appearance = Appearance.Button;
                cbShowPin.Width = 32;
                cbShowPin.Height = 25;
                cbShowPin.Image = KeepassBuiltinImage.Get("B19x07_3BlackDots");
                cbShowPin.CheckedChanged += (s, e) => pinInput.EnableProtection(!cbShowPin.Checked);
                mainLayout.Controls.Add(cbShowPin, 3, currentMainRow);


                if (isRetry) {
                    currentMainRow++;

                    var lblRetry = new Label();
                    lblRetry.Text = Strings.PinPromptDialog_WrongPin;
                    lblRetry.Font = new Font(lblRetry.Font, FontStyle.Bold);
                    lblRetry.Dock = DockStyle.Fill;
                    lblRetry.TextAlign = ContentAlignment.MiddleLeft;
                    lblRetry.Anchor = AnchorStyles.Left | AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Right;
                    mainLayout.Controls.Add(lblRetry, 1, currentMainRow);
                    mainLayout.SetColumnSpan(lblRetry, mainLayout.ColumnCount - 2);
                }


                currentMainRow += 2;

                var lblSeparator = new Label();
                lblSeparator.Height = 2;
                lblSeparator.Padding = new Padding(0);
                lblSeparator.Margin = new Padding(0);
                lblSeparator.Dock = DockStyle.Fill;
                lblSeparator.BorderStyle = BorderStyle.Fixed3D;

                mainLayout.Controls.Add(lblSeparator, 0, currentMainRow);
                mainLayout.SetColumnSpan(lblSeparator, mainLayout.ColumnCount);


                currentMainRow += 2;

                var buttonsLayout = new TableLayoutPanel();
                buttonsLayout.AutoSize = true;
                buttonsLayout.GrowStyle = TableLayoutPanelGrowStyle.FixedSize;
                buttonsLayout.Dock = DockStyle.Fill;
                buttonsLayout.ColumnCount = 3;
                buttonsLayout.RowCount = 1;
                buttonsLayout.Margin = new Padding(0);
                buttonsLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
                buttonsLayout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
                buttonsLayout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
                buttonsLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));

                mainLayout.Controls.Add(buttonsLayout, 1, currentMainRow);
                mainLayout.SetColumnSpan(buttonsLayout, mainLayout.ColumnCount - 2);

                var cbRememberPin = new CheckBox();
                cbRememberPin.Text = Strings.PinPromptDialog_RememberPin;
                buttonsLayout.Controls.Add(cbRememberPin, 0, 0);

                var btnOk = new Button();
                btnOk.Text = Strings.AnyUI_ButtonOK;
                btnOk.Size = UIConstants.DefaultButtonSize;
                btnOk.DialogResult = DialogResult.OK;
                btnOk.Enabled = false;
                btnOk.Click += (s, e) => this.result = new PinPromptDialogResult(pinInput.TextEx.ToPortable(), cbRememberPin.Checked);
                buttonsLayout.Controls.Add(btnOk, 1, 0);
                this.AcceptButton = btnOk;

                pinInput.TextChanged += (s, e) => btnOk.Enabled = pinInput.TextLength > 0;

                var btnCancel = new Button();
                btnCancel.Text = Strings.AnyUI_ButtonCancel;
                btnCancel.Size = UIConstants.DefaultButtonSize;
                btnCancel.DialogResult = DialogResult.Cancel;
                buttonsLayout.Controls.Add(btnCancel, 2, 0);
                this.CancelButton = btnCancel;

                this.ResumeLayout();

                // invoke after all components have been added and layout was resumed
                // -> this ensures correct size, also on scaled displays
                BannerFactory.CreateBannerEx(this, banner, KeepassBuiltinImage.Get("B48x48_KGPG_Key2"), "Enter PIN", description);
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

            protected override void OnClosed(EventArgs e) {
                base.OnClosed(e);

                GlobalWindowManager.RemoveWindow(this);

                if (this.Owner != null) {
                    this.Owner.Enabled = true;
                }
            }

            bool IGwmWindow.CanCloseWithoutDataLoss { get { return true; } }

        }
    }
}