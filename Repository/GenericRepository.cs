using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Linq.Expressions;

namespace Cyber20ShadowServer.Repository
{
    public class GenericRepository<T> : IGenericRepository<T> where T : class
    {
        private readonly Cyber20ShadowEntities _context = null;
        private readonly DbSet<T> table = null;

        public GenericRepository()
        {
            this._context = new Cyber20ShadowEntities();
            table = _context.Set<T>();
        }

        public GenericRepository(Cyber20ShadowEntities _context)
        {
            this._context = _context;
            table = _context.Set<T>();
        }

        public IEnumerable<T> GetAll()
        {
            return table.ToList();
        }

        public T GetById(object id)
        {
            return table.Find(id);
        }

        public void Insert(T obj)
        {
            table.Add(obj);
        }

        public void Update(T obj)
        {
            table.Attach(obj);
            _context.Entry(obj).State = EntityState.Modified;
        }

        public void Delete(object id)
        {
            T existing = table.Find(id);
            table.Remove(existing);
        }

        public void Save()
        {
            _context.SaveChanges();
        }

        public IEnumerable<T> Find(Expression<Func<T, bool>> predicate)
        {
            return _context.Set<T>().Where<T>(predicate).ToList();
        }
    }
}