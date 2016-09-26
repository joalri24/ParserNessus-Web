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
    public class VulnerabilitiesController : ApiController
    {
        private ApplicationDbContext db = new ApplicationDbContext();

        // GET: api/Vulnerabilities
        public IQueryable<Vulnerability> GetVulnerabilities()
        {
            return db.Vulnerabilities;
        }

        // GET: api/Vulnerabilities/5
        [ResponseType(typeof(Vulnerability))]
        public async Task<IHttpActionResult> GetVulnerability(int id)
        {
            Vulnerability vulnerability = await db.Vulnerabilities.FindAsync(id);
            if (vulnerability == null)
            {
                return NotFound();
            }

            return Ok(vulnerability);
        }

        // PUT: api/Vulnerabilities/5
        [ResponseType(typeof(void))]
        public async Task<IHttpActionResult> PutVulnerability(int id, Vulnerability vulnerability)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            if (id != vulnerability.Id)
            {
                return BadRequest();
            }

            db.Entry(vulnerability).State = EntityState.Modified;

            try
            {
                await db.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!VulnerabilityExists(id))
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

        // POST: api/Vulnerabilities
        [ResponseType(typeof(Vulnerability))]
        public async Task<IHttpActionResult> PostVulnerability(Vulnerability vulnerability)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            db.Vulnerabilities.Add(vulnerability);
            await db.SaveChangesAsync();

            return CreatedAtRoute("DefaultApi", new { id = vulnerability.Id }, vulnerability);
        }

        // DELETE: api/Vulnerabilities/5
        [ResponseType(typeof(Vulnerability))]
        public async Task<IHttpActionResult> DeleteVulnerability(int id)
        {
            Vulnerability vulnerability = await db.Vulnerabilities.FindAsync(id);
            if (vulnerability == null)
            {
                return NotFound();
            }

            db.Vulnerabilities.Remove(vulnerability);
            await db.SaveChangesAsync();

            return Ok(vulnerability);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                db.Dispose();
            }
            base.Dispose(disposing);
        }

        private bool VulnerabilityExists(int id)
        {
            return db.Vulnerabilities.Count(e => e.Id == id) > 0;
        }
    }
}