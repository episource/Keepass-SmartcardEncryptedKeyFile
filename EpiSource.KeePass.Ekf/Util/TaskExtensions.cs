using System;
using System.Runtime.ExceptionServices;
using System.Threading.Tasks;
using System.Windows.Threading;

using EpiSource.Unblocker.Hosting;

namespace EpiSource.KeePass.Ekf.Util {
    public static class TaskExtensions {
        public static async Task IgnoreResult<T>(this Task<T> task) {
            await task;
        }

        public static async Task<T> AddDefaultResult<T>(this Task task) {
            await task;
            return default(T);
        }

        /// <summary>
        /// Block until given task has finished. Keeps message pump active while blocking, therefore any UI remains
        /// responsive.
        /// </summary>
        /// <param name="task">Task to wait for.</param>
        /// <typeparam name="T">Result of task.</typeparam>
        /// <returns>Result of task.</returns>
        /// 
        /// <exception cref="TaskCanceledException">The task was canceled.</exception>
        /// <exception cref="TaskCrashedException">The task crashed, i.e. the corresponding process exited unexpectedly.</exception>
        /// <exception cref="Exception">Task specific exceptions.</exception>
        /// <exception cref="AggregateException">If multiple exceptions occured.</exception>
        public static T AwaitWithMessagePump<T>(this Task<T> task) {
            var dispatcherFrame = new DispatcherFrame();

            task.ContinueWith(t => dispatcherFrame.Continue = false,
                TaskContinuationOptions.ExecuteSynchronously);
            Dispatcher.PushFrame(dispatcherFrame);

            try {
                return task.Result;
            } catch (AggregateException e) {
                if (e.InnerExceptions.Count == 1 && e.InnerException != null) {
                    ExceptionDispatchInfo.Capture(e.InnerException).Throw();
                }

                throw;
            }
        }

        /// <summary>
        /// Block until given task has finished. Keeps message pump active while blocking, therefore any UI remains
        /// responsive.
        /// </summary>
        /// <param name="task">Task to wait for.</param>
        /// <exception cref="TaskCanceledException">The task was canceled.</exception>
        /// <exception cref="TaskCrashedException">The task crashed, i.e. the corresponding process exited unexpectedly.</exception>
        /// <exception cref="Exception">Task specific exceptions.</exception>
        /// <exception cref="AggregateException">If multiple exceptions occured.</exception>
        public static void AwaitWithMessagePump(this Task task) {
            task.AddDefaultResult<object>().AwaitWithMessagePump();
        }

    }
}