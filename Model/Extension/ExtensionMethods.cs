using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cyber20ShadowServer.Model.Extension
{
    public static class ExtensionMethods
    {
        public static IEnumerable<TA> Except<TA, TB, TK>(
       this IEnumerable<TA> a,
       IEnumerable<TB> b,
       Func<TA, TK> selectKeyA,
       Func<TB, TK> selectKeyB,
       IEqualityComparer<TK> comparer = null)
        {
            return a.Where(aItem => !b.Select(bItem => selectKeyB(bItem)).Contains(selectKeyA(aItem), comparer));
        }
    }
}
