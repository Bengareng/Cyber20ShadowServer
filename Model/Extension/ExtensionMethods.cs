using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
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

        public static void WriteToCSV<T>(this IEnumerable<T> items, string path)
        {
            Type itemType = typeof(T);
            var props = itemType.GetProperties(BindingFlags.Public | BindingFlags.Instance)
                                .OrderBy(p => p.Name);

            using (var writer = new StreamWriter(path))
            {
                writer.WriteLine(string.Join(", ", props.Select(p => p.Name)));

                foreach (var item in items)
                {
                    writer.WriteLine(string.Join(", ", props.Select(p => p.GetValue(item, null))));
                }
            }

        }
        public static T ToObject<T>(this Object fromObject)
        {
            return JsonConvert.DeserializeObject<T>(JsonConvert.SerializeObject(fromObject));
        }


        public static List<T> ToObjectList<T>(this Object fromObject)
        {
            return JsonConvert.DeserializeObject<List<T>>(JsonConvert.SerializeObject(fromObject));
        }

    }
}
