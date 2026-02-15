using System;
using System.Linq.Expressions;
using System.Threading;
using System.Threading.Tasks;

using EpiSource.KeePass.Ekf.Plugin;
using EpiSource.KeePass.Ekf.Util;
using EpiSource.Unblocker;
using EpiSource.Unblocker.Hosting;

using KeePass.UI;

namespace EpiSource.KeePass.Ekf.UI {
    public sealed partial class SmartcardOperationDialogFactory {
        public static readonly TimeSpan UsuallyShortTaskRecommendedDialogDelay = TimeSpan.FromSeconds(1);

        private const int gracefulAbortTimeoutMs = 100;
        
        /// disable unblocker (background process) to simplify debugging
        private const bool debugWithoutUnblocker = 
            #if NO_UNBLOCKER
            true;
            #else
            false;
            #endif

        // A dedicated worker process pool is used:
        // - smartcard operations involve native code without support for cancellation; hence the process needs
        // to be killed to cancel
        // - Some smartcards require the pin to be entered just once. This is bound to the requesting process. Hence
        // the standby timeout is chosen quite long.
        // - Worker limit is set to one, such that smartcard operations are not done in parallel.
        // - Unblocker creates the first worker process on first invocation only, therefore there's no need for
        // explicit lazy initialization
        // ReSharper disable once RedundantArgumentDefaultValue
        private readonly UnblockerHost smartcardWorker;

        public SmartcardOperationDialogFactory(PluginConfiguration pluginConfiguration) {
            this.smartcardWorker = new UnblockerHost(
                standbyDelay: TimeSpan.FromSeconds(500000), maxWorkers: 1,
                bootstrapMode: pluginConfiguration.UnblockerBootstrapMode,
                debug: pluginConfiguration.DebugMode ? DebugMode.Console : DebugMode.None);
        }    
            
        #region DoCryptoWithMessagePump factory methods

        public void DoCryptoWithMessagePump(
            Expression<Action<CancellationToken>> cryptoOperation, CancellationToken ct = default(CancellationToken),
            TimeSpan? showDialogDelay = null
        ) {
            this.DoCryptoAsync(cryptoOperation, ct, showDialogDelay).AwaitWithMessagePump();
        }

        public IMethodInvocationResult<TTarget> DoCryptoWithMessagePump<TTarget>(TTarget target,
            Expression<Action<CancellationToken, TTarget>> cryptoOperation,
            CancellationToken ct = default(CancellationToken), TimeSpan? showDialogDelay = null) {
            return this.DoCryptoAsync(target, cryptoOperation, ct, showDialogDelay).AwaitWithMessagePump();
        }

        public TReturn DoCryptoWithMessagePump<TReturn>(
            Expression<Func<CancellationToken, TReturn>> cryptoOperation, CancellationToken ct = default(CancellationToken),
            TimeSpan? showDialogDelay = null
        ) {
            return this.DoCryptoAsync(cryptoOperation, ct, showDialogDelay).AwaitWithMessagePump();
        }

        public IFunctionInvocationResult<TTarget, TReturn> DoCryptoWithMessagePump<TTarget, TReturn>(TTarget target,
            Expression<Func<CancellationToken, TTarget, TReturn>> cryptoOperation,
            CancellationToken ct = default(CancellationToken), TimeSpan? showDialogDelay = null) {
            return this.DoCryptoAsync(target, cryptoOperation, ct, showDialogDelay).AwaitWithMessagePump();
        }

        public void DoCryptoWithMessagePumpShort(
            Expression<Action<CancellationToken>> cryptoOperation, CancellationToken ct = default(CancellationToken)
        ) {
            this.DoCryptoAsync(cryptoOperation, ct, UsuallyShortTaskRecommendedDialogDelay).AwaitWithMessagePump();
        }

        public IMethodInvocationResult<TTarget> DoCryptoWithMessagePumpShort<TTarget>(TTarget target,
            Expression<Action<CancellationToken, TTarget>> cryptoOperation,
            CancellationToken ct = default(CancellationToken)) {
            return this.DoCryptoAsync(target, cryptoOperation, ct, UsuallyShortTaskRecommendedDialogDelay).AwaitWithMessagePump();
        }

        public TReturn DoCryptoWithMessagePumpShort<TReturn>(
            Expression<Func<CancellationToken, TReturn>> cryptoOperation, CancellationToken ct = default(CancellationToken)
        ) {
            return this.DoCryptoAsync(cryptoOperation, ct, UsuallyShortTaskRecommendedDialogDelay).AwaitWithMessagePump();
        }

        public IFunctionInvocationResult<TTarget, TReturn> DoCryptoWithMessagePumpShort<TTarget, TReturn>(TTarget target,
            Expression<Func<CancellationToken, TTarget, TReturn>> cryptoOperation,
            CancellationToken ct = default(CancellationToken)) {
            return this.DoCryptoAsync(target, cryptoOperation, ct, UsuallyShortTaskRecommendedDialogDelay).AwaitWithMessagePump();
        }

        #endregion

        #region DoCryptoAsync

        public async Task DoCryptoAsync(
            Expression<Action<CancellationToken>> cryptoOperation, CancellationToken ct = default(CancellationToken),
            TimeSpan? showDialogDelay = null
        ) {
            await this.DoCryptoImpl(InvocationRequest.FromExpression(cryptoOperation), ct, showDialogDelay)
                .ConfigureAwait(false);
        }

        public async Task<IMethodInvocationResult<TTarget>> DoCryptoAsync<TTarget>(TTarget target,
            Expression<Action<CancellationToken, TTarget>> cryptoOperation, CancellationToken ct = default(CancellationToken),
            TimeSpan? showDialogDelay = null) {
            return await this.DoCryptoImpl(InvocationRequest.FromExpression(cryptoOperation, target), ct, showDialogDelay);
        }

        public async Task<TReturn> DoCryptoAsync<TReturn>(
            Expression<Func<CancellationToken, TReturn>> cryptoOperation, CancellationToken ct = default(CancellationToken),
            TimeSpan? showDialogDelay = null
        ) {
            return (await this.DoCryptoImpl(InvocationRequest.FromExpression(cryptoOperation), ct, showDialogDelay)
                .ConfigureAwait(false)).Result;
        }

        public async Task<IFunctionInvocationResult<TTarget, TReturn>> DoCryptoAsync<TTarget, TReturn>(TTarget target, Expression<Func<CancellationToken, TTarget, TReturn>> cryptoOperation, CancellationToken ct = default(CancellationToken),
            TimeSpan? showDialogDelay = null) {
            return await this.DoCryptoImpl(InvocationRequest.FromExpression(cryptoOperation, target), ct, showDialogDelay)
                .ConfigureAwait(false);
        }

        #endregion DoCryptoAsync

        #region DoCrypto Implementation

        private async Task<IFunctionInvocationResult<TTarget, TReturn>> DoCryptoImpl<TTarget, TReturn>(
            InvocationRequest<TTarget, TReturn> cryptoOperationRequest, CancellationToken ct, TimeSpan? showDialogDelay
        ) {
            // on request: disable unblocker (background process) to simplify debugging
#pragma warning disable CS0162
            if (debugWithoutUnblocker) {
                var synchronousResult = cryptoOperationRequest.Invoke(ct);
                return new InvocationResult<TTarget, TReturn>(cryptoOperationRequest.Target, synchronousResult, true);
            }
#pragma warning restore CS0162

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
    }
}