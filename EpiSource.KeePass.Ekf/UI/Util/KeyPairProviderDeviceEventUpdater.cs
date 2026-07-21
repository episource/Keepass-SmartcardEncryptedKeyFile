using System;
using System.Threading.Tasks;
using System.Windows.Forms;

using EpiSource.KeePass.Ekf.Util.Windows;
using EpiSource.Unblocker.Hosting;

namespace EpiSource.KeePass.Ekf.UI.Util {
    
    public class KeyPairProviderDeviceEventUpdater : IDisposable {
        
        private readonly IKeyPairProvider keyPairProvider;
        private readonly UIFactory uiFactory;
        
        private Timer refreshDelayTimer;
        private NativeDeviceEvents deviceEventListener;
        private bool refreshSmartcardOperationPending = false;

        public KeyPairProviderDeviceEventUpdater(IKeyPairProvider keyPairProvider, UIFactory uiFactory, int delayMs = 250) {
            this.keyPairProvider = keyPairProvider;
            this.uiFactory = uiFactory;
            
            this.refreshDelayTimer = new Timer() {
                Interval = delayMs
            };
            this.refreshDelayTimer.Tick += this.OnTick;
        }
        
        // invoked on UI thread
        public event EventHandler<EventArgs> Changed;

        public IKeyPairProvider KeyPairProvider {
            get { return this.keyPairProvider; }
        }

        public void StartUpdates() {
            if (this.refreshDelayTimer == null) {
                throw new ObjectDisposedException("KeyPairProviderDeviceEventUpdater instance has been disposed");
            }
            
            if (this.deviceEventListener == null) {
                this.deviceEventListener = new NativeDeviceEvents();

                this.deviceEventListener.AnyDeviceEvent += (sender, args) => {
                    if (args.Reason == NativeDeviceEvents.NotificationReason.Unknown) {
                        // ignore unrelated events
                        return;
                    }

                    // Timer internally marshalls to the UI thread - no Control#Invoke required
                    this.refreshDelayTimer.Restart();
                };
            }
        }
        
        public void Dispose() {
            if (this.deviceEventListener != null) {
                this.deviceEventListener.Dispose();
                this.deviceEventListener = null;
            }
            if (this.refreshDelayTimer != null) {
                this.refreshDelayTimer.Stop();
                this.refreshDelayTimer.Tick -= OnTick;
                this.refreshDelayTimer.Dispose();
                this.refreshDelayTimer = null;
            }
        }

        private void OnTick(object sender, EventArgs e) {
            this.refreshDelayTimer.Stop();

            if (this.refreshSmartcardOperationPending) {
                this.refreshDelayTimer.Restart();
                return;
            } 
            
            IFunctionInvocationResult<IKeyPairProvider, bool> refreshResult;
            try {
                this.refreshSmartcardOperationPending = true;
                refreshResult = this.uiFactory.SmartcardOperationDialog.DoCryptoWithMessagePumpShort(
                    this.keyPairProvider, (ct, _) => _.Refresh());
            } catch (TaskCanceledException) {
                // that's fine - skip this refresh
                return;
            } finally {
                this.refreshSmartcardOperationPending = false;
            }

            var hasChanged = this.keyPairProvider.Refresh(refreshResult.PostInvocationTarget);
            if (hasChanged && this.Changed != null) {
                // Timer events run on UI thread, therefore Changed event, too
                this.Changed(this, EventArgs.Empty);
            }
        }
    }
    
}