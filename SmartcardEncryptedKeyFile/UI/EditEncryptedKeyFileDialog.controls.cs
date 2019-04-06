using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;
using System.Windows.Forms.VisualStyles;

using KeePass.UI;

using ContentAlignment = System.Drawing.ContentAlignment;

namespace Episource.KeePass.EKF.UI {
    public partial class EditEncryptedKeyFileDialog : Form {
        private readonly TableLayoutPanel layout = new TableLayoutPanel();
        private readonly CustomListViewEx keyListView = new CustomListViewEx();
        private const string noChangeCaption = "(none)";
        private const int maxAutoWidth = 800;

        private int listViewRowHeight = 0;
        private TextBox txtKeySource;
        
        private Label lblValidationError;
        private Button btnOk;

        private readonly Dictionary<string, KeyPairModel> keyList = new Dictionary<string, KeyPairModel>();

        // ReSharper disable once InconsistentNaming
        private void InitializeUI() {
            this.SuspendLayout();

            this.AutoSize = true;
            this.AutoScaleMode = UIConstants.AutoScaleMode;
            this.AutoScaleDimensions = UIConstants.AutoScaleDimensions;
            this.Padding = new Padding(12);
            this.MinimumSize = new Size(520, 150);
            this.Size = new Size( this.MinimumSize.Width,  300); // width autosized depending on content

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
                Height = UIConstants.DefaultButtonHeight,
                Width = UIConstants.DefaultButtonWidth,
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
                Height = UIConstants.DefaultButtonHeight,
                Width = UIConstants.DefaultButtonWidth,
                TabIndex = 0
            };
            this.layout.Controls.Add(this.btnOk, column: 2, row: 5);
            this.AcceptButton = this.btnOk;
            
            var btnCancel = new Button {
                Text = "Cancel",
                DialogResult = DialogResult.Cancel,
                Height = UIConstants.DefaultButtonHeight,
                Width = UIConstants.DefaultButtonWidth,
                TabIndex = 1
            };
            this.layout.Controls.Add(btnCancel, column: 3, row: 5);
            this.CancelButton = btnCancel;
        }

        private void InitializeKeyList() {
            const FontStyle actionFont = FontStyle.Bold; 
            const string newKeyAction = "add";
            const string delKeyAction = "remove";

            this.keyListView.Dock = DockStyle.Fill;
            this.keyListView.AutoSize = true;
            this.keyListView.FullRowSelect = true;
            this.keyListView.CheckBoxes = true;
            this.keyListView.View = View.Details;
            this.keyListView.HeaderStyle = ColumnHeaderStyle.Nonclickable;
            this.keyListView.ShowItemToolTips = false;
            this.keyListView.TabIndex = 4;
            
            // width "-2" -> auto size respecting header width
            this.keyListView.Columns.Add("☑ Change", -2);
            this.keyListView.Columns.Add("Subject", -2);
            this.keyListView.Columns.Add("Serial#", -2);
            this.keyListView.Columns.Add("Provider", -2);

            UIUtil.SetExplorerTheme(this.keyListView, false);
            this.layout.Controls.Add(this.keyListView, 0, 4);
            this.layout.SetColumnSpan(this.keyListView, this.layout.ColumnCount);
            
            // Add every possible change value for proper sizing
            // Dummy items will be deleted after size has been calculated (form load event)
            this.keyListView.Items.Add(newKeyAction).Font = new Font(this.keyListView.Font, actionFont);
            this.keyListView.Items.Add(delKeyAction).Font = new Font(this.keyListView.Font, actionFont);
            this.keyListView.Items.Add(noChangeCaption);
            
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
                    item.Font = new Font(item.Font, actionFont);
                    
                    if (model.NextAuthorization == KeyPairModel.Authorization.Authorized) {
                        item.Text = newKeyAction;
                    } else {
                        item.Text = delKeyAction;
                    }
                } else {
                    item.Font = null;
                    item.Text = noChangeCaption;
                }

                this.OnContentChanged();
            };
            
            // show tooltip for all columns
            ToolTip listViewTooltip = null;
            this.keyListView.MouseMove += (sender, args) => {
                var hitTest = this.keyListView.HitTest(args.Location);
                if (listViewTooltip != null) {
                    if (hitTest == null || hitTest.Item == null || hitTest.Item != listViewTooltip.Tag) {
                        listViewTooltip.Hide(this.keyListView);
                        listViewTooltip.RemoveAll();
                        listViewTooltip.Dispose();
                        listViewTooltip = null;
                    }
                } else if (hitTest.Item != null) {
                    listViewTooltip = new ToolTip {
                        Tag = hitTest.Item,
                        Active = true,
                        ShowAlways = true
                    };
                    listViewTooltip.SetToolTip(this.keyListView, hitTest.Item.ToolTipText);
                }
            };

            // make sure the last columns spans all the remaining width
            this.Resize += (sender, args) => { 
                // -2: auto size using header and content & last column stretches
                this.keyListView.Columns[this.keyListView.Columns.Count - 1].Width = -2;
            };

            this.Load += (sender, args) => {
                // we know there are at least two dummy items
                this.listViewRowHeight = this.keyListView.Items[1].Position.Y - this.keyListView.Items[0].Position.Y;
                
                // remove dummy items used for autosizing
                for (var i = this.keyListView.Items.Count - 1; i >= 0; --i) {
                    var item = this.keyListView.Items[i];
                    if (item.Tag == null) { // dummy for width calculation
                        this.keyListView.Items.Remove(item);
                    }
                }

                // autosize width depending on content
                var wantedSize = this.keyListView.Columns.OfType<ColumnHeader>().Sum(c => c.Width);
                var maxDelta = Math.Max(0, maxAutoWidth - this.Width);
                this.Width += Math.Min(maxDelta, 
                    wantedSize - this.keyListView.Width + 3 * SystemInformation.VerticalScrollBarWidth / 2);
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
            
            var item = new ListViewItem(noChangeCaption);
            item.UseItemStyleForSubItems = false;
            item.Tag = keyModel;
            item.Checked = keyModel.NextAuthorization == KeyPairModel.Authorization.Authorized;
            item.SubItems.Add(cert.Subject);
            item.SubItems.Add(cert.SerialNumber);
            item.SubItems.Add(this.DescribeKeyProvider(keyModel.Provider));
            item.ToolTipText = "Thumbprint: " + cert.Thumbprint;
            
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