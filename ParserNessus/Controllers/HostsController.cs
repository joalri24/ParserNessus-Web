using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Data.Entity.Infrastructure;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Description;
using ParserNessus.Models;

namespace ParserNessus.Controllers
{
    public class HostsController : ApiController
    {
        private ApplicationDbContext db = new ApplicationDbContext();

        // GET: api/Hosts
        public IQueryable<Host> GetHosts()
        {
            return db.Hosts;
        }

        // GET: api/Hosts/5
        [ResponseType(typeof(Host))]
        public async Task<IHttpActionResult> GetHost(int id)
        {
            Host host = await db.Hosts.FindAsync(id);
            if (host == null)
            {
                return NotFound();
            }

            return Ok(host);
        }

        // PUT: api/Hosts/5
        [ResponseType(typeof(void))]
        public async Task<IHttpActionResult> PutHost(int id, Host host)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            if (id != host.Id)
            {
                return BadRequest();
            }

            db.Entry(host).State = EntityState.Modified;

            try
            {
                await db.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!HostExists(id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }

            return StatusCode(HttpStatusCode.NoContent);
        }

        // POST: api/Hosts
        [ResponseType(typeof(Host))]
        public async Task<IHttpActionResult> PostHost(Host host)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            db.Hosts.Add(host);
            await db.SaveChangesAsync();

            return CreatedAtRoute("DefaultApi", new { id = host.Id }, host);
        }

        // DELETE: api/Hosts/5
        [ResponseType(typeof(Host))]
        public async Task<IHttpActionResult> DeleteHost(int id)
        {
            Host host = await db.Hosts.FindAsync(id);
            if (host == null)
            {
                return NotFound();
            }

            db.Hosts.Remove(host);
            await db.SaveChangesAsync();

            return Ok(host);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                db.Dispose();
            }
            base.Dispose(disposing);
        }

        private bool HostExists(int id)
        {
            return db.Hosts.Count(e => e.Id == id) > 0;
        }
    }
}