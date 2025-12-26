using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace EpiSource.KeePass.Ekf.Util {
    public static class EnumerableExtensions {
        public static IEnumerable<T> DistinctByStructure<T>(this IEnumerable<T> enumerable) where T : IStructuralEquatable {
            return enumerable.Distinct(new StructuralEqualityComparer<T>());
        }
        
        public static IEnumerable<TSource> DistinctByStructure<TSource, TKey>(this IEnumerable<TSource> enumerable, Func<TSource, TKey> keySelector) where TKey : IStructuralEquatable {
            var seenKeys = new HashSet<TKey>(new StructuralEqualityComparer<TKey>());
            foreach (var element in enumerable) {
                if (seenKeys.Add(keySelector(element))) {
                    yield return element;
                }
            }
        }
        
        public static IEnumerable<TSource> DistinctBy<TSource, TKey>(this IEnumerable<TSource> enumerable, Func<TSource, TKey> keySelector) {
            var seenKeys = new HashSet<TKey>();
            foreach (var element in enumerable) {
                if (seenKeys.Add(keySelector(element))) {
                    yield return element;
                }
            }
        }

        private class StructuralEqualityComparer<T> : IEqualityComparer<T> where T : IStructuralEquatable {

            public bool Equals(T x, T y)  { 
                return StructuralComparisons.StructuralEqualityComparer.Equals(x, y);
            }
            public int GetHashCode(T obj) {
                return StructuralComparisons.StructuralEqualityComparer.GetHashCode(obj);
            }
        }
    }
}