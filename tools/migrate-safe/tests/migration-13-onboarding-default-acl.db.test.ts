// Behaviour test for Migration 13 against a DISPOSABLE LOCAL database in which migration 13 has already been applied
// (post-state only; every check runs inside a transaction that is rolled back). Skipped unless all of these are set:
//   CONSOLE_TEST_ACL_DB_URL     postgres-role URL, loopback host only (the role Console runner uses; non-superuser)
//   CONSOLE_TEST_ACL_SUPER_URL  superuser URL to the same database, loopback only. Used for SET ROLE to roles postgres is not a member of
//                               (anon / authenticated / service_role / sobae_ops_executor / sobae_app_login). Without it those two actual-call tests are
//                               reported as SKIPPED (not run, not passed).
//   CONSOLE_TEST_ACL_DB_TOKEN   must equal the database comment 'sobae-disposable-test-db:v1:<token>' (guard against pointing at a real database)
// Target verification (before ANY connection runs a CREATE/GRANT/SET ROLE): both URLs are loopback and have the same port and database name; on EVERY open
// connection (admin and, if used, super) current_database() equals the URL's database name and the database comment equals the token; the identity facts
// (database name, database OID, server port, postmaster start time, comment) must be present and identical across the two connections. A missing fact, a
// mismatch or an error in this step stops the run (non-zero) before any writing statement. Connections that were opened are still closed independently.
// "Actual call" = a call made after SET ROLE inside a superuser session. It proves the privilege decision, not a login, a pooler or Data API reachability.
// Failure reporting: every failure of a step is re-thrown as a NEW error that carries only a step name, an error code that matches a fixed format
// (SQLSTATE-like 5 chars, E<NAME> or ERR_<NAME>; anything else is shown as 'invalid-code' / 'no-code') and, for this file's own assert labels, that label.
// The original exception (message, stack, cause, properties) is never passed on. NOT covered: output that the postgres driver or the Node runtime
// writes outside of these exceptions (this file does not control it), and a code value that happens to match the allowed format.
import assert from 'node:assert/strict'
import { after, before, describe, it } from 'node:test'
import postgres from 'postgres'
import { isLoopbackHost } from '../src/conn.ts'

const DB_URL = process.env.CONSOLE_TEST_ACL_DB_URL
const SUPER_URL = process.env.CONSOLE_TEST_ACL_SUPER_URL
const TOKEN = process.env.CONSOLE_TEST_ACL_DB_TOKEN
const ENABLED = Boolean(DB_URL && TOKEN)

const OWNER = 'sobae_onboarding_executor'
const OWNER_ONLY_ACL = `{${OWNER}=X/${OWNER}}`
const failures: string[] = []

// ---- safe failure reporting ------------------------------------------------------------------------------------------
const CODE_RE = /^(?:[0-9A-Z]{5}|E[A-Z0-9_]{2,30}|ERR_[A-Z0-9_]{1,40})$/
const LABEL_RE = /^[A-Za-z0-9_ .:()\-,]{1,100}$/
function codeOf(e: unknown): string {
  try {
    if (typeof e !== 'object' || e === null) return 'no-code'
    const c: unknown = (e as { code?: unknown }).code
    if (typeof c !== 'string') return 'no-code'
    return CODE_RE.test(c) ? c : 'invalid-code'
  } catch {
    return 'invalid-code'
  }
}
function labelOf(e: unknown): string {
  try {
    if (e instanceof assert.AssertionError && e.generatedMessage === false && LABEL_RE.test(e.message)) return `:${e.message}`
  } catch {
    // fall through: no label
  }
  return ''
}
class SafeFailure extends Error {
  constructor(msg: string) {
    super(msg)
    this.name = 'Migration13TestFailure'
    this.stack = `${this.name}: ${msg}` // no frames, no cause
  }
}
const stepFail = (step: string, e: unknown) => {
  failures.push(`${step}:${codeOf(e)}`)
}
function toSafe(step: string, e: unknown): SafeFailure {
  if (e instanceof SafeFailure) return e
  return new SafeFailure(`${step}:${codeOf(e)}${labelOf(e)}`)
}
const reject = (reason: string): never => {
  throw new SafeFailure(`before:${reason}`)
}

interface Identity {
  db: string
  oid: string
  port: string
  started: string
  comment: string
}
const ID_KEYS = ['db', 'oid', 'port', 'started', 'comment'] as const

describe('migration 13: onboarding default routine EXECUTE (disposable local DB, post-state)', { skip: !ENABLED }, () => {
  let admin: postgres.Sql | null = null // postgres role (non-superuser)
  let sup: postgres.Sql | null = null // superuser (optional)
  let verified = false // true only after EVERY target verification succeeded
  let adminOpen = false
  let supOpen = false

  function target(url: string): { db: string; port: string } {
    const u = new URL(url)
    if (!isLoopbackHost(u.hostname)) reject('not-loopback')
    const db = decodeURIComponent(u.pathname.replace(/^\//, ''))
    if (db === '') reject('no-database-name')
    return { db, port: u.port === '' ? '5432' : u.port }
  }
  function open(url: string): postgres.Sql {
    return postgres(url, { max: 1, onnotice: () => {}, connect_timeout: 10 })
  }

  async function identify(sql: postgres.Sql, uriDb: string): Promise<Identity> {
    const rows = await sql.unsafe(
      `select current_database()::text as db, (select oid::text from pg_database where datname = current_database()) as oid, inet_server_port()::text as port, pg_postmaster_start_time()::text as started, shobj_description((select oid from pg_database where datname = current_database()), 'pg_database') as comment`,
    )
    const r = rows[0] as Record<string, unknown> | undefined
    if (!r) return reject('identity-unavailable')
    const out: Partial<Identity> = {}
    for (const k of ID_KEYS) {
      const v = r[k]
      if (typeof v !== 'string' || v === '') return reject('identity-unavailable')
      out[k] = v
    }
    const id = out as Identity
    if (id.db !== uriDb) reject('database-name-mismatch')
    if (id.comment !== `sobae-disposable-test-db:v1:${TOKEN}`) reject('token-mismatch')
    return id
  }

  async function closeAll(): Promise<void> {
    // Each connection is closed independently; a failure is recorded and never turns an earlier failure into success.
    if (admin && adminOpen) {
      adminOpen = false
      try { await admin.end({ timeout: 5 }) } catch (e) { stepFail('end-admin', e) }
    }
    if (sup && supOpen) {
      supOpen = false
      try { await sup.end({ timeout: 5 }) } catch (e) { stepFail('end-super', e) }
    }
  }

  before(async () => {
    try {
      // 1) URL-level checks. No connection exists yet.
      const a = target(DB_URL!)
      const s = SUPER_URL ? target(SUPER_URL) : null
      if (s && (s.db !== a.db || s.port !== a.port)) reject('url-target-mismatch')
      // 2) Open and identify. These are read-only SELECTs; nothing is created or granted until every check below has passed.
      admin = open(DB_URL!)
      adminOpen = true
      if (SUPER_URL) {
        sup = open(SUPER_URL)
        supOpen = true
      }
      const idA = await identify(admin, a.db)
      if (sup && s) {
        const idS = await identify(sup, s.db)
        for (const k of ID_KEYS) if (idA[k] !== idS[k]) reject('connection-target-mismatch')
      }
      // 3) Migration 13 must be recorded exactly once.
      const rows = await admin.unsafe(`select count(*)::text as n from console.migration_history where filename = '13_restrict_onboarding_executor_default_routine_execute.sql'`)
      if ((rows[0] as { n?: string } | undefined)?.n !== '1') reject('migration-13-not-applied')
      verified = true
    } catch (e) {
      verified = false
      const safe = toSafe('before', e)
      try { await closeAll() } catch (e2) { stepFail('end-after-before-failure', e2) }
      throw safe
    }
  })

  // Every test body goes through run(): it refuses to run unless the target was verified, and it converts any exception into a SafeFailure.
  async function run(step: string, fn: () => Promise<void>): Promise<void> {
    if (!verified || !admin) throw new SafeFailure(`${step}:target-not-verified`)
    try {
      await fn()
    } catch (e) {
      throw toSafe(step, e)
    }
  }

  // Run fn inside BEGIN ... ROLLBACK on the given connection (max: 1, so BEGIN and ROLLBACK use the same session).
  async function inTx<T>(sql: postgres.Sql, step: string, fn: () => Promise<T>): Promise<T> {
    await sql.unsafe('BEGIN')
    try {
      return await fn()
    } finally {
      try { await sql.unsafe('ROLLBACK') } catch (e) { stepFail(`rollback:${step}`, e) }
    }
  }
  // SQLSTATE of a statement run as `role` (SET LOCAL ROLE); null = succeeded. Uses a savepoint so the transaction survives.
  async function callAs(sql: postgres.Sql, role: string, stmt: string): Promise<string | null> {
    await sql.unsafe('SAVEPOINT s_call')
    try {
      await sql.unsafe(`SET LOCAL ROLE ${role}`)
      await sql.unsafe(stmt)
      await sql.unsafe('RESET ROLE')
      await sql.unsafe('RELEASE SAVEPOINT s_call')
      return null
    } catch (e) {
      await sql.unsafe('ROLLBACK TO SAVEPOINT s_call')
      await sql.unsafe('RELEASE SAVEPOINT s_call')
      return codeOf(e)
    }
  }
  const hasPriv = async (sql: postgres.Sql, role: string, fn: string): Promise<boolean> =>
    (await sql.unsafe(`select has_function_privilege('${role}', '${fn}'::regprocedure, 'EXECUTE') as b`))[0].b as boolean
  const publicInAcl = async (sql: postgres.Sql, fn: string): Promise<boolean> =>
    (await sql.unsafe(`select exists (select 1 from pg_proc p, aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a where p.oid = '${fn}'::regprocedure and a.grantee = 0 and a.privilege_type = 'EXECUTE') as b`))[0].b as boolean
  const aclText = async (sql: postgres.Sql, fn: string): Promise<string> =>
    (await sql.unsafe(`select coalesce(proacl::text, 'NULL') as a from pg_proc where oid = '${fn}'::regprocedure`))[0].a as string

  it('pg_default_acl: exactly one row for the onboarding role: global, type f, direct grantee owner only, no schema-scoped rows', () =>
    run('t1-default-acl', async () => {
      const rows = await admin!.unsafe(`select defaclnamespace::oid::int as ns, defaclobjtype::text as t, defaclacl::text as acl from pg_default_acl where defaclrole = '${OWNER}'::regrole`)
      assert.equal(rows.length, 1, 'onboarding default ACL row count')
      assert.equal(rows[0].ns, 0, 'onboarding default ACL is global')
      assert.equal(rows[0].t, 'f', 'onboarding default ACL type f')
      assert.equal(rows[0].acl, OWNER_ONLY_ACL, 'onboarding default ACL grantee')
      const pg = await admin!.unsafe(`select defaclacl::text as acl from pg_default_acl where defaclrole = 'postgres'::regrole and defaclnamespace = 0 and defaclobjtype = 'f'`)
      assert.equal(pg.length, 1, 'postgres default ACL row count')
      assert.equal(pg[0].acl, '{postgres=X/postgres}', 'postgres default ACL unchanged') // the existing postgres default (Migration 215 of the main repo) is untouched
    }))

  it('postgres reaches onboarding-created routines by inheritance (USAGE); SET is a separate fact', () =>
    run('t2-inherit', async () => {
      const [r] = await admin!.unsafe(`select pg_has_role('postgres', '${OWNER}', 'USAGE') as usage, pg_has_role('postgres', '${OWNER}', 'SET') as sett`)
      assert.equal(r.usage, true, 'postgres USAGE on onboarding')
      assert.equal(r.sett, true, 'postgres SET on onboarding')
    }))

  it('a routine created directly by onboarding (FUNCTION/PROCEDURE × INVOKER/DEFINER): ACL is the owner only, PUBLIC is not in the ACL, catalog EXECUTE is false for ops, Data API roles and the app login', () =>
    run('t3-create-by-onboarding', async () => {
      const a = admin!
      await inTx(a, 'create-by-onboarding', async () => {
        await a.unsafe(`SET LOCAL ROLE ${OWNER}`)
        await a.unsafe(`create function console.zz13_f_inv() returns int language sql as 'select 1'`)
        await a.unsafe(`create function console.zz13_f_def() returns int language sql security definer as 'select 1'`)
        await a.unsafe(`create procedure console.zz13_p_inv() language sql as 'select 1'`)
        await a.unsafe(`create procedure console.zz13_p_def() language sql security definer as 'select 1'`)
        await a.unsafe('RESET ROLE')
        for (const fn of ['console.zz13_f_inv()', 'console.zz13_f_def()', 'console.zz13_p_inv()', 'console.zz13_p_def()']) {
          assert.equal(await aclText(a, fn), OWNER_ONLY_ACL, `acl ${fn}`)
          assert.equal(await publicInAcl(a, fn), false, `public ${fn}`)
          for (const role of ['anon', 'authenticated', 'service_role', 'sobae_ops_executor', 'sobae_app_login', 'sobae_app_runtime']) assert.equal(await hasPriv(a, role, fn), false, `${role} ${fn}`)
          assert.equal(await hasPriv(a, OWNER, fn), true, `owner ${fn}`)
          assert.equal(await hasPriv(a, 'postgres', fn), true, `postgres ${fn}`) // inherited from the owner role
        }
      })
    }))

  it('actual calls (superuser SET ROLE): before any explicit GRANT, ops/anon/authenticated/service_role/app_login get 42501; the owner can call; after an explicit GRANT to ops, ops can call and PUBLIC still cannot', { skip: !SUPER_URL }, () =>
    run('t4-actual-calls', async () => {
      const s = sup!
      await inTx(s, 'actual-calls', async () => {
        await s.unsafe(`SET LOCAL ROLE ${OWNER}`)
        await s.unsafe(`create function console.zz13_call() returns int language sql security definer as 'select 1'`)
        await s.unsafe(`create procedure console.zz13_proc() language sql security definer as 'select 1'`)
        await s.unsafe('RESET ROLE')
        for (const role of ['anon', 'authenticated', 'service_role', 'sobae_ops_executor', 'sobae_app_login', 'sobae_app_runtime']) {
          assert.equal(await callAs(s, role, 'select console.zz13_call()'), '42501', `${role} function`)
          assert.equal(await callAs(s, role, 'call console.zz13_proc()'), '42501', `${role} procedure`)
        }
        assert.equal(await callAs(s, OWNER, 'select console.zz13_call()'), null, 'owner function')
        assert.equal(await callAs(s, OWNER, 'call console.zz13_proc()'), null, 'owner procedure')
        await s.unsafe(`grant execute on function console.zz13_call() to sobae_ops_executor`)
        await s.unsafe(`grant execute on procedure console.zz13_proc() to sobae_ops_executor`)
        assert.equal(await callAs(s, 'sobae_ops_executor', 'select console.zz13_call()'), null, 'ops function after grant')
        assert.equal(await callAs(s, 'sobae_ops_executor', 'call console.zz13_proc()'), null, 'ops procedure after grant')
        assert.equal(await callAs(s, 'anon', 'select console.zz13_call()'), '42501', 'anon after grant')
        assert.equal(await publicInAcl(s, 'console.zz13_call()'), false, 'public after grant')
      })
    }))

  it('ops cannot create routines or schemas (actual attempts: 42501); only the session-private pg_temp works', { skip: !SUPER_URL }, () =>
    run('t5-ops-create', async () => {
      const s = sup!
      await inTx(s, 'ops-create', async () => {
        assert.equal(await callAs(s, 'sobae_ops_executor', `create function console.zz13_o() returns int language sql as 'select 1'`), '42501', 'ops create function console')
        assert.equal(await callAs(s, 'sobae_ops_executor', `create function public.zz13_o() returns int language sql as 'select 1'`), '42501', 'ops create function public')
        assert.equal(await callAs(s, 'sobae_ops_executor', `create procedure console.zz13_o() language sql as 'select 1'`), '42501', 'ops create procedure console')
        assert.equal(await callAs(s, 'sobae_ops_executor', 'create schema zz13_o'), '42501', 'ops create schema')
      })
    }))

  it('creation paths: postgres-created then OWNER moved (no PUBLIC); CREATE OR REPLACE keeps the ACL; a new signature and DROP + re-create get the new default', () =>
    run('t6-creation-paths', async () => {
      const a = admin!
      await inTx(a, 'creation-paths', async () => {
        await a.unsafe(`create function console.zz13_b() returns int language sql security definer as 'select 1'`)
        await a.unsafe(`alter function console.zz13_b() owner to ${OWNER}`)
        assert.equal(await publicInAcl(a, 'console.zz13_b()'), false, 'moved no public')
        assert.equal(await aclText(a, 'console.zz13_b()'), OWNER_ONLY_ACL, 'moved acl')
        await a.unsafe(`set local role ${OWNER}`)
        await a.unsafe(`create function console.zz13_c() returns int language sql as 'select 1'`)
        await a.unsafe('reset role')
        await a.unsafe(`grant execute on function console.zz13_c() to sobae_ops_executor`)
        const before = await aclText(a, 'console.zz13_c()')
        await a.unsafe(`set local role ${OWNER}`)
        await a.unsafe(`create or replace function console.zz13_c() returns int language sql as 'select 2'`)
        await a.unsafe('reset role')
        assert.equal(await aclText(a, 'console.zz13_c()'), before, 'create or replace keeps acl') // explicit GRANT survives CREATE OR REPLACE
        await a.unsafe(`set local role ${OWNER}`)
        await a.unsafe(`create function console.zz13_c(int) returns int language sql as 'select 3'`)
        await a.unsafe('drop function console.zz13_c()')
        await a.unsafe(`create function console.zz13_c() returns int language sql as 'select 4'`)
        await a.unsafe('reset role')
        assert.equal(await aclText(a, 'console.zz13_c(int)'), OWNER_ONLY_ACL, 'new signature acl')
        assert.equal(await aclText(a, 'console.zz13_c()'), OWNER_ONLY_ACL, 're-created acl') // re-created: back to the default, the earlier explicit GRANT is gone
      })
    }))

  it('existing 7 functions and 2 views are as before: owner onboarding, no PUBLIC/Data API EXECUTE, ops EXECUTE, ops SELECT on the views', () =>
    run('t7-existing-objects', async () => {
      const a = admin!
      const fns = ['console.fn_apply_onboarding(jsonb,text)', 'console.fn_dryrun_onboarding(jsonb,text)', 'console.fn_suspend_organization(uuid,text,text)',
        'console.fn_reactivate_organization(uuid,text,text)', 'console.fn_terminate_organization(uuid,text,text,date)', 'console.fn_suspend_office(uuid,text,text)', 'console.fn_reactivate_office(uuid,text,text)']
      for (const fn of fns) {
        const [r] = await a.unsafe(`select proowner::regrole::text as o, prosecdef as d, proacl::text as acl from pg_proc where oid = '${fn}'::regprocedure`)
        assert.equal(r.o, OWNER, `owner ${fn}`)
        assert.equal(r.d, true, `secdef ${fn}`)
        assert.equal(r.acl, `{${OWNER}=X/${OWNER},sobae_ops_executor=X/${OWNER}}`, `acl ${fn}`)
        assert.equal(await publicInAcl(a, fn), false, `public ${fn}`)
        for (const role of ['anon', 'authenticated', 'service_role']) assert.equal(await hasPriv(a, role, fn), false, `${role} ${fn}`)
        assert.equal(await hasPriv(a, 'sobae_ops_executor', fn), true, `ops ${fn}`)
      }
      const views = await a.unsafe(`select c.oid::regclass::text as v, c.relowner::regrole::text as o, has_table_privilege('sobae_ops_executor', c.oid, 'SELECT') as ops_sel from pg_class c where c.relnamespace = 'console'::regnamespace and c.relkind = 'v' order by 1`)
      assert.deepEqual(views.map((v) => [v.v, v.o, v.ops_sel]), [['console.v_office_summary', OWNER, true], ['console.v_organization_summary', OWNER, true]])
    }))

  it('no residue: no zz13_ routine or zz13 schema remains', () =>
    run('t8-no-residue', async () => {
      const [r] = await admin!.unsafe(`select (select count(*) from pg_proc where proname like 'zz13\\_%')::int as fns, (select count(*) from pg_namespace where nspname like 'zz13%')::int as schemas`)
      assert.equal(r.fns, 0, 'residue routines')
      assert.equal(r.schemas, 0, 'residue schemas')
    }))

  after(async () => {
    // Each cleanup step is attempted independently; any failure fails the run (below). Nothing here turns an earlier failure into success.
    if (verified && admin) {
      try {
        const [r] = await admin.unsafe(`select (select count(*) from pg_proc where proname like 'zz13\\_%')::int as n`)
        if (r.n !== 0) failures.push('residue:fns')
      } catch (e) { stepFail('residue-check', e) }
    }
    try { await closeAll() } catch (e) { stepFail('close-all', e) }
    if (failures.length > 0) throw new SafeFailure(`cleanup/step failures: ${failures.join(', ')}`)
  })
})
