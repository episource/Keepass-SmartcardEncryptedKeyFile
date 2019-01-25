using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;

using KeePass.UI;

namespace Episource.KeePass.EKF.UI {
    public partial class EditEncryptedKeyFileDialog : Form {
        // height chosen to match a single line text box
        private const int DefaultButtonHeight = 22;
        private const int DefaultButtonWidth = 75;

        private readonly TableLayoutPanel layout = new TableLayoutPanel();
        private readonly CustomListViewEx keyListView = new CustomListViewEx();

        private TextBox txtKeySource;
        
        private Label lblValidationError;
        private Button btnOk;

        private readonly Dictionary<string, KeyPairModel> keyList = new Dictionary<string, KeyPairModel>();

        // ReSharper disable once InconsistentNaming
        private void InitializeUI() {
            this.SuspendLayout();

            this.AutoSize = true;
            this.AutoScaleMode = AutoScaleMode.Font;
            this.AutoScaleDimensions = new SizeF(6F, 13F);
            this.Padding = new Padding(12);
            this.MinimumSize = new Size(520, 150);
            this.Size = new Size( 780,  300);

            this.layout.Top = 0;
            this.layout.Left = 0;
            this.layout.AutoSize = true;
            this.layout.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            this.layout.Dock = DockStyle.Fill;
            this.layout.ColumnCount = 4;
            this.layout.RowCount = 6;
            this.layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            this.layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, width: 100.0f));
            this.layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            this.layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            this.layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            this.layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            this.layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            this.layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            this.layout.RowStyles.Add(new RowStyle(SizeType.Percent, height: 100.0f));
            this.layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            this.Controls.Add(this.layout);

            this.InitializeTopBar();
            //this.InitializeSeparator();
            this.InitializeKeyList();
            this.InitializeDialogButtons();

            this.RenewKeySourceDisplay();
            this.ResumeLayout();
        }

        private void InitializeTopBar() {
            var lblDb = new Label {
                Text = "Database:",
                AutoSize = true,
                Anchor = AnchorStyles.Left | AnchorStyles.Top | AnchorStyles.Bottom,
                TextAlign = ContentAlignment.MiddleLeft
            };
            this.layout.Controls.Add(lblDb, column: 0, row: 0);

            var txtDb = new TextBox {
                ReadOnly = true,
                Text = this.dbPath.Path,
                AutoSize = true,
                Anchor = AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Top | AnchorStyles.Bottom,
                TabStop = false
            };
            this.layout.Controls.Add(txtDb, column: 1, row: 0);
            this.layout.SetColumnSpan(txtDb, value: 3);

            var lblKeySource = new Label {
                Text = "Key Source:",
                AutoSize = true,
                Anchor = AnchorStyles.Left | AnchorStyles.Top | AnchorStyles.Bottom,
                TextAlign = ContentAlignment.MiddleLeft
            };
            this.layout.Controls.Add(lblKeySource, column: 0, row: 1);

            this.txtKeySource = new TextBox {
                ReadOnly = true,
                AutoSize = true,
                Anchor = AnchorStyles.Left | AnchorStyles.Right,
                TabStop = false
            };
            
            this.layout.Controls.Add(this.txtKeySource, column: 1, row: 1);
            this.layout.SetColumnSpan(this.txtKeySource, value: 2);

            // TODO: SplitButtonEx currently supports windows only! DropDown not shown on other platforms.
            var btnExport = new SplitButtonEx {
                Text = "Export",
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowOnly,
                Height = DefaultButtonHeight,
                Width = DefaultButtonWidth,
                UseVisualStyleBackColor = true,
                SplitDropDownMenu = new CustomContextMenuStripEx()
            };
            btnExport.Click += (sender, args) => this.ExportKey();
            
            var btnActiveKey = new ToolStripMenuItem("Select active key file");
            btnActiveKey.Enabled = this.permitNewKey;
            btnActiveKey.Click += (sender, args) => this.RevertToActiveKey();
            btnExport.SplitDropDownMenu.Items.Add(btnActiveKey);
            
            var btnRandomKey = new ToolStripMenuItem("Generate random key");
            btnRandomKey.Enabled = this.permitNewKey;
            btnRandomKey.Click += (sender, args) => this.GenerateRandomKey();
            btnExport.SplitDropDownMenu.Items.Add(btnRandomKey);
            
            var btnImportKey = new ToolStripMenuItem("Import key file");
            btnImportKey.Enabled = this.permitNewKey;
            btnImportKey.Click += (sender, args) => this.ImportKey();
            btnExport.SplitDropDownMenu.Items.Add(btnImportKey);

            this.layout.Controls.Add(btnExport, 3, 1);
        }

        // ReSharper disable once UnusedMember.Local
        private void InitializeSeparator() {
            var hLine = new Label {
                AutoSize = false,
                Height = 2,
                BorderStyle = BorderStyle.Fixed3D,
                Anchor = AnchorStyles.Left | AnchorStyles.Right
            };
            this.layout.Controls.Add(hLine, column: 0, row: 2);
            this.layout.SetColumnSpan(hLine, this.layout.ColumnCount);
        }

        private void InitializeDialogButtons() {
            this.lblValidationError = new Label {
                AutoSize = true,
                ForeColor = SystemColors.GrayText,
                TabStop = false
            };
            this.layout.Controls.Add(this.lblValidationError, column: 0, row: 5);
            this.layout.SetColumnSpan(this.lblValidationError, value: 2);
            
            this.btnOk = new Button {
                Text = "OK",
                DialogResult = DialogResult.OK,
                Height = DefaultButtonHeight,
                Width = DefaultButtonWidth,
                TabIndex = 0
            };
            this.layout.Controls.Add(this.btnOk, column: 2, row: 5);
            this.AcceptButton = this.btnOk;
            
            var btnCancel = new Button {
                Text = "Cancel",
                DialogResult = DialogResult.Cancel,
                Height = DefaultButtonHeight,
                Width = DefaultButtonWidth,
                TabIndex = 1
            };
            this.layout.Controls.Add(btnCancel, column: 3, row: 5);
            this.CancelButton = btnCancel;
        }

        private void InitializeKeyList() {
            this.keyListView.Dock = DockStyle.Fill;
            this.keyListView.AutoSize = true;
            this.keyListView.FullRowSelect = true;
            this.keyListView.CheckBoxes = true;
            this.keyListView.View = View.Details;
            this.keyListView.HeaderStyle = ColumnHeaderStyle.Nonclickable;
            this.keyListView.TabIndex = 4;

            // width "-2" -> auto size respecting header width
            this.keyListView.Columns.Add(text: "☑ Thumbprint", width: -2);
            this.keyListView.Columns.Add(text: "Subject", width: -2);
            this.keyListView.Columns.Add(text: "Current", width: -2);
            this.keyListView.Columns.Add(text: "Provider", width: -2);

            UIUtil.SetExplorerTheme(this.keyListView, bUseListFont: false);
            this.layout.Controls.Add(this.keyListView, column: 0, row: 4);
            this.layout.SetColumnSpan(this.keyListView, this.layout.ColumnCount);
            
            // prevent changing column width
            this.keyListView.ColumnWidthChanging += (sender, args) => {
                args.Cancel = true;
                args.NewWidth = this.keyListView.Columns[args.ColumnIndex].Width;
            };
            
            // don't highlight selection
            this.keyListView.ItemSelectionChanged += (sender, args) => {
                if (args.IsSelected) {
                    args.Item.Selected = false;
                }
            };

            // check on click
            this.keyListView.MouseClick += (sender, args) => {
                var hitTest = this.keyListView.HitTest(args.Location);
                if (hitTest.Item != null && hitTest.Location != ListViewHitTestLocations.StateImage) {
                    hitTest.Item.Checked = !hitTest.Item.Checked;
                }
            };
            
            // handle state change of checkbox
            this.keyListView.ItemCheck += (sender, args) => {
                var item = this.keyListView.Items[args.Index];
                var model = (KeyPairModel) item.Tag;
                model.NextAuthorization = args.NewValue == CheckState.Checked ? 
                    KeyPairModel.Authorization.Authorized : KeyPairModel.Authorization.Rejected;

                if (model.CurrentAuthorization != model.NextAuthorization) {
                    if (model.NextAuthorization == KeyPairModel.Authorization.Authorized) {
                        item.Font = new Font(item.Font, FontStyle.Underline);
                    } else {
                        item.Font = new Font(item.Font, FontStyle.Strikeout);
                    }
                } else {
                    item.Font = null;
                }

                this.OnContentChanged();
            };

            // make sure the last columns spans all the remaining width
            this.Resize += (sender, args) => { 
                // -2: auto size using header and content & last column stretches
                this.keyListView.Columns[this.keyListView.Columns.Count - 1].Width = -2; 
            };
        }

        private void OnContentChanged() {
            this.btnOk.Enabled = this.ValidateInput();
            if (this.btnOk.Enabled) {
                this.lblValidationError.Text = "";
            }
        }
        
        private void ShowValidationError(string message) {
            this.lblValidationError.Text = message;
        }
        
        private bool AddKeyIfNew(KeyPairModel keyModel) {
            var cert = keyModel.KeyPair.Certificate;
            if (this.keyList.ContainsKey(cert.Thumbprint)) {
                return false;
            }
            
            var item = new ListViewItem(cert.Thumbprint);
            item.Tag = keyModel;
            item.Checked = keyModel.NextAuthorization == KeyPairModel.Authorization.Authorized;
            item.SubItems.Add(cert.Subject);
            item.SubItems.Add(this.DescribeAuthorization(keyModel.CurrentAuthorization));
            item.SubItems.Add(this.DescribeKeyProvider(keyModel.Provider));
            
            this.keyList.Add(cert.Thumbprint, keyModel);
            this.keyListView.Items.Add(item);
            
            // autosize
            this.keyListView.AutoResizeColumns(ColumnHeaderAutoResizeStyle.ColumnContent);
            this.keyListView.AutoResizeColumns(ColumnHeaderAutoResizeStyle.HeaderSize);
            
            return true;
        }

        private void RenewKeySourceDisplay() {
            this.txtKeySource.Text = "(" + this.DescribeKeySource() + ")";
        }
    }
}