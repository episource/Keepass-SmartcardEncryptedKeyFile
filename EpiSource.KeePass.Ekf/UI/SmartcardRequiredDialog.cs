using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;

using EpiSource.KeePass.Ekf.Crypto;

using Episource.KeePass.EKF.Resources;

using EpiSource.KeePass.Ekf.Util.Windows;

using KeePass.UI;

using Timer = System.Windows.Forms.Timer;

namespace EpiSource.KeePass.Ekf.UI {
    public sealed class SmartcardRequiredDialog : Form {
        private static readonly string stateConnected = Strings.SmartcardRequiredDialog_KeyStateConnected;
        private static readonly string stateNotConnected = Strings.SmartcardRequiredDialog_KeyStateNotConnected;

        private bool loaded = false;

        private readonly TableLayoutPanel layout = new TableLayoutPanel();
        private readonly CustomListViewEx keyListView = new CustomListViewEx();
        private Button btnOk;

        private NativeDeviceEvents deviceEventListener;
        private readonly Timer refreshDelayTimer = new Timer() { Interval = 250 };
        private readonly Timer redrawAfterScrollDelayTimer = new Timer() { Interval = 150 };

        private readonly IKeyPairProvider keyPairProvider;

        public static IKeyPair ChooseKeyPairForDecryption(EncryptedKeyFile ekf, Form owner = null) {
            var keyPairProvider = new DefaultKeyPairProvider(ekf);
            return ChooseKeyPairForDecryption(keyPairProvider, owner);
        }
        
        public static IKeyPair ChooseKeyPairForDecryption(IKeyPairProvider keyProvider, Form owner = null) {
            var candidates = keyProvider.GetAuthorizedKeyPairs();
            if (candidates.Count == 0) {
                return null;
            }

            var readyKeyPair = candidates.FirstOrDefault(kp => kp.KeyPair.IsReadyForDecrypt);
            if (readyKeyPair != null) {
                return readyKeyPair.KeyPair;
            }

            var dialog = new SmartcardRequiredDialog(null, keyProvider);
            var result = dialog.ShowDialog();
            if (result != DialogResult.OK || dialog.keyListView.CheckedItems.Count == 0) {
                return null;
            }

            return dialog.keyListView.CheckedItems.Cast<ListViewItem>()
                         .Select(i => i.Tag as KeyPairModel)
                         // ReSharper disable once PossibleNullReferenceException
                         .Select(m => m.KeyPair).First();
        }
        
        private SmartcardRequiredDialog(Form owner, IKeyPairProvider keyPairProvider) {
            if (owner != null) {
                this.Owner = owner;
            }

            this.keyPairProvider = keyPairProvider;
            
            this.InitializeUI();
            this.ReplaceList();

            this.refreshDelayTimer.Tick += this.OnRefreshRequested;
        }
        
        private void InitializeUI() {
            this.SuspendLayout();

            this.StartPosition = FormStartPosition.CenterParent;

            this.AutoSize = true;
            this.Size = new Size(0, 0);
            this.AutoScaleMode = UIConstants.AutoScaleMode;
            this.AutoScaleDimensions = UIConstants.AutoScaleDimensions;
            this.Padding = new Padding(12);

            this.Text = Strings.SmartcardRequiredDialog_DialogTitle;

            this.MinimizeBox = false;
            this.MaximizeBox = false;
            this.FormBorderStyle = FormBorderStyle.Sizable;
            this.ShowInTaskbar = false;

            this.layout.Top = 0;
            this.layout.Left = 0;
            this.layout.AutoSize = true;
            this.layout.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            this.layout.GrowStyle = TableLayoutPanelGrowStyle.FixedSize;
            this.layout.Dock = DockStyle.Fill;
            this.layout.ColumnCount = 2;
            this.layout.RowCount = 3;
            this.layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            this.layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            this.layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            this.layout.RowStyles.Add(new RowStyle(SizeType.Percent, 1.0f));
            this.layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            this.Controls.Add(this.layout);

            var iconBox = new PictureBox {
                Width = SystemIcons.Information.Width,
                Height = SystemIcons.Information.Height,
                Image = SystemIcons.Information.ToBitmap(),
                Margin = new Padding(0, 0, this.Padding.Right / 2, this.Padding.Bottom / 2)
            };
            this.layout.Controls.Add(iconBox, 0, 0);
            this.layout.SetRowSpan(iconBox, 2);

            var maxLabelSize = new Size(350, 0);
            var titleText = new Label {
                MaximumSize = maxLabelSize,
                Text = Strings.SmartcardRequiredDialog_DialogText,
                AutoSize = true,
            };
            titleText.Font = new Font(titleText.Font, FontStyle.Bold);
            this.layout.Controls.Add(titleText, 1, 0);

            this.InitializeKeyList();

            var layoutBtn = new TableLayoutPanel {
                Dock = DockStyle.Fill,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                RowCount = 2, // one more row needed to work around autosize bug
                ColumnCount = 2,
                DockPadding = { All = 0},
                Padding = new Padding(0) ,
                ColumnStyles = {
                    new ColumnStyle(SizeType.Percent, 0.5f),
                    new ColumnStyle(SizeType.Percent, 0.5f)
                },
                RowStyles = { new RowStyle(SizeType.AutoSize) }
            };
            this.layout.Controls.Add(layoutBtn, 0, 2);
            this.layout.SetColumnSpan(layoutBtn, this.layout.ColumnCount);
            this.btnOk = new Button {
                Text = Strings.AnyUI_ButtonOK,
                DialogResult = DialogResult.OK,
                Height = UIConstants.DefaultButtonHeight,
                Width = UIConstants.DefaultButtonWidth,
                MaximumSize = new Size(UIConstants.DefaultButtonWidth, UIConstants.DefaultButtonHeight),
                Anchor = AnchorStyles.Right,
                TabIndex = 1,
                Enabled = false
            };
            layoutBtn.Controls.Add(this.btnOk, 0, 0);
            var btnCancel = new Button {
                Text = Strings.AnyUI_ButtonCancel,
                DialogResult = DialogResult.Cancel,
                Height = UIConstants.DefaultButtonHeight,
                Width = UIConstants.DefaultButtonWidth,
                MaximumSize = new Size(UIConstants.DefaultButtonWidth, UIConstants.DefaultButtonHeight),
                Anchor = AnchorStyles.Left,
                TabIndex = 1
            };
            layoutBtn.Controls.Add(btnCancel, 1, 0);

            this.ResumeLayout();
        }

        private void InitializeKeyList() {
            this.keyListView.Dock = DockStyle.Fill;
            this.keyListView.AutoSize = true;
            this.keyListView.FullRowSelect = true;
            this.keyListView.CheckBoxes = true;
            this.keyListView.View = View.Details;
            this.keyListView.HeaderStyle = ColumnHeaderStyle.Nonclickable;
            this.keyListView.ShowItemToolTips = false;
            this.keyListView.TabIndex = 4;

            this.keyListView.OwnerDraw = true;
            var keyListViewScrollDetectionReferenceLocation = Point.Empty;
            this.keyListView.DrawItem += (sender, args) => {
                var tag = args.Item.Tag as KeyPairModel;
                var enabled = tag != null && tag.KeyPair.IsReadyForDecrypt;
                
                args.DrawBackground();

                if (args.Item.Focused) {
                    ControlPaint.DrawFocusRectangle(args.Graphics, args.Bounds, args.Item.ForeColor, args.Item.BackColor);
                }
                
                var checkboxRect = args.Bounds;
                checkboxRect.Y += 1;
                checkboxRect.X += 2;
                checkboxRect.Height -= 2;
                checkboxRect.Width = checkboxRect.Height;
                var buttonStateChecked = enabled && args.Item.Checked ? ButtonState.Checked : 0;
                var buttonStateInactive = !enabled ? ButtonState.Inactive : 0;
                ControlPaint.DrawCheckBox(args.Graphics, checkboxRect, 
                    ButtonState.Flat | buttonStateChecked | buttonStateInactive);

                var itemTextBounds = checkboxRect;
                itemTextBounds.Y += 1;
                itemTextBounds.X += checkboxRect.Width + 1;
                itemTextBounds.Width = args.Item.SubItems.Count > 0 ? args.Item.SubItems[args.Item.SubItems.Count - 1].Bounds.X : args.Bounds.Width;
                itemTextBounds.Height = checkboxRect.Height + 1;
                TextRenderer.DrawText(args.Graphics, args.Item.Text, args.Item.Font, itemTextBounds, enabled ? args.Item.ForeColor : SystemColors.GrayText, TextFormatFlags.NoClipping);
                
                // note: first subitem is item itself!
                foreach (var subItem in args.Item.SubItems.Cast<ListViewItem.ListViewSubItem>().Skip(1)) {
                    var subItemTextBounds = subItem.Bounds;
                    subItemTextBounds.X += 2;
                    subItemTextBounds.Y = itemTextBounds.Y;
                    subItemTextBounds.Width -= 2;
                    subItemTextBounds.Height = checkboxRect.Height;
                    TextRenderer.DrawText(args.Graphics, subItem.Text, subItem.Font, subItemTextBounds, enabled ? subItem.ForeColor : SystemColors.GrayText, TextFormatFlags.Default);
                }

                args.DrawDefault = false;

                // detect scrolling and redraw control after scrolling has finished (using delay)
                if (args.ItemIndex == 0 && args.Bounds.Location != keyListViewScrollDetectionReferenceLocation) {
                    keyListViewScrollDetectionReferenceLocation = args.Bounds.Location;
                    RestartFormsTimer(this.redrawAfterScrollDelayTimer);
                }
            };
            this.keyListView.DrawColumnHeader += (sender, args) => args.DrawDefault = true;
            this.keyListView.DrawSubItem += (sender, args) => args.DrawDefault = false;

            this.redrawAfterScrollDelayTimer.Tick += (sender, args) => {
                this.redrawAfterScrollDelayTimer.Stop();
                this.keyListView.Invalidate();
            };
            
            // width "-2" -> auto size respecting header width
            const int autoSizeHeader = -2;
            this.keyListView.Columns.Add(Strings.SmartcardRequiredDialog_ColumnReady, autoSizeHeader);
            this.keyListView.Columns.Add(Strings.SmartcardRequiredDialog_ColumnSubject, autoSizeHeader);
            this.keyListView.Columns.Add(Strings.SmartcardRequiredDialog_ColumnSerial, autoSizeHeader);
            this.keyListView.Columns.Add(Strings.SmartcardRequiredDialog_ColumnProvider, autoSizeHeader);

            UIUtil.SetExplorerTheme(this.keyListView, false);
            this.layout.Controls.Add(this.keyListView, 1, 1);
            
            // Add every possible state value for proper sizing
            // Dummy items will be deleted after size has been calculated (form load event)
            this.keyListView.Items.Add(stateConnected);
            this.keyListView.Items.Add(stateNotConnected);
            
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
            // permit only one checked item
            this.keyListView.ItemCheck += (sender, args) => {
                if (args.NewValue == CheckState.Checked) {
                    var model = this.keyListView.Items[args.Index].Tag as KeyPairModel;
                    if (model == null || !model.KeyPair.IsReadyForDecrypt) {
                        args.NewValue = args.CurrentValue;
                        return;
                    }
                    
                    for (int i = 0; i < this.keyListView.Items.Count; ++i) {
                        if (i != args.Index) {
                            this.keyListView.Items[i].Checked = false;
                        }
                    }
                }

                // do this after programmatically unchecking items!
                this.btnOk.Enabled = args.NewValue == CheckState.Checked;
                if (this.btnOk.Enabled) {
                    this.btnOk.Focus();
                }
            };

            // make sure the last columns spans all the remaining width
            this.Resize += (sender, args) => { 
                // -2: auto size using header and content & last column stretches
                this.keyListView.Columns[this.keyListView.Columns.Count - 1].Width = -2;
            };

            this.Load += (sender, args) => {
                // remove dummy items used for autosizing
                for (var i = this.keyListView.Items.Count - 1; i >= 0; --i) {
                    var item = this.keyListView.Items[i];
                    if (item.Tag == null) { // dummy for width calculation
                        this.keyListView.Items.Remove(item);
                    }
                }

                // autosize width depending on content
                var wantedSize = this.keyListView.Columns.OfType<ColumnHeader>().Sum(c => c.Width);
                var maxDelta = Math.Max(0, UIConstants.MaxAutoWidth - this.Width);
                this.Width += Math.Min(maxDelta, 
                    wantedSize - this.keyListView.Width + 3 * SystemInformation.VerticalScrollBarWidth / 2);

                this.loaded = true;
            };
            
        }

        private void ReplaceList() {
            this.keyListView.BeginUpdate();
            var prevCheckedItems = new HashSet<string>();
            try {
                if (this.loaded) {
                    // note: result == false does not imply, that IsReadyForDecrypt to be unchanged!
                    // => replace list independent of result
                    this.keyPairProvider.Refresh();

                    prevCheckedItems = this.keyListView.CheckedItems.Cast<ListViewItem>()
                                           .Select(i => i.Tag as KeyPairModel)
                                           .Select(m => m.KeyPair.Certificate.Thumbprint)
                                           .ToHashSet();
                    this.keyListView.Items.Clear();
                    
                    // re-enabled by checking an item
                    this.btnOk.Enabled = false; 
                }

                ListViewItem firstAvailItem = null;
                var availItemCount = 0;
                foreach (var kpm in this.keyPairProvider.GetAuthorizedKeyPairs()
                                      .GroupBy(kp => kp.KeyPair.Certificate.Thumbprint)
                                      .Select(g => g.First())) {

                    var cert = kpm.KeyPair.Certificate;
                    var stateText = stateNotConnected;
                    if (kpm.KeyPair.IsReadyForDecrypt) {
                        stateText = stateConnected;
                    }

                    var item = new ListViewItem(stateText);
                    item.UseItemStyleForSubItems = false;
                    item.Tag = kpm;
                    item.SubItems.Add(cert.Subject);
                    item.SubItems.Add(cert.SerialNumber);
                    item.SubItems.Add(kpm.Provider.ToString());
                    item.ToolTipText = string.Format(Strings.Culture, Strings.SmartcardRequiredDialog_LabelThumbprint, cert.Thumbprint);
                    this.keyListView.Items.Add(item);

                    if (kpm.KeyPair.IsReadyForDecrypt) {
                        item.Checked = prevCheckedItems.Contains(cert.Thumbprint);
                        firstAvailItem = firstAvailItem ?? item;
                        availItemCount++;
                    }
                }

                if (firstAvailItem != null && this.keyListView.CheckedItems.Count == 0) {
                    firstAvailItem.Checked = true;
                }

                if (this.loaded && availItemCount == 1) {
                    this.DialogResult = DialogResult.OK;
                    this.Close();
                    return;
                }
            }
            finally {
                if (!this.Disposing && !this.IsDisposed) {
                    this.keyListView.EndUpdate();
                }
            }

            // autosize
            this.keyListView.AutoResizeColumns(ColumnHeaderAutoResizeStyle.ColumnContent);
            this.keyListView.AutoResizeColumns(ColumnHeaderAutoResizeStyle.HeaderSize);
        }

        private void OnRefreshRequested(object sender, EventArgs args) {
            this.refreshDelayTimer.Stop();
            this.ReplaceList();
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

            if (this.deviceEventListener == null) {
                this.deviceEventListener = new NativeDeviceEvents();

                this.deviceEventListener.AnyDeviceEvent += (sender, args) => {
                    if (args.Reason == NativeDeviceEvents.NotificationReason.Unknown) {
                        // ignore unrelated events
                        return;
                    }
                    
                    if (this.InvokeRequired) {
                        this.Invoke((MethodInvoker)(() => RestartFormsTimer(this.refreshDelayTimer)));
                    }
                    else {
                        RestartFormsTimer(this.refreshDelayTimer);
                    }
                    
                };
            }
        }

        protected override void OnClosed(EventArgs e) {
            base.OnClosed(e);

            if (this.Owner != null) {
                this.Owner.Enabled = true;
            }

            if (this.deviceEventListener != null) {
                this.deviceEventListener.Dispose();
                this.deviceEventListener = null;
            }
        }

        private static void RestartFormsTimer(Timer t) {
            t.Stop();
            
            // restart timer: force change of interval; else interval continues!
            var modulo = t.Interval % 5;
            t.Interval += modulo == 0 ? 1 : -1 * modulo;
            
            t.Start();
        }

    }
}