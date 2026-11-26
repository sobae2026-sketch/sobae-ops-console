// Static checks for sql/migrations/13_restrict_onboarding_executor_default_routine_execute.sql (no database needed).
// The behaviour (what the statement does to pg_default_acl and to newly created routines) is checked by
// migration-13-onboarding-default-acl.db.test.ts against a disposable local database.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { describe, it } from 'node:test'
import { fileURLToPath } from 'node:url'
import { analyze, loadMigrationFiles } from '../src/files.ts'
import { findForbidden, stripSqlNoise } from '../src/sqlscan.ts'

const HERE = dirname(fileURLToPath(import.meta.url))
const DIR = join(HERE, '..', '..', '..', 'sql', 'migrations')
const NAME = '13_restrict_onboarding_executor_default_routine_execute.sql'
const MAIN_STATEMENT = 'ALTER DEFAULT PRIVILEGES FOR ROLE sobae_onboarding_executor REVOKE EXECUTE ON ROUTINES FROM PUBLIC'
const sql = readFileSync(join(DIR, NAME), 'utf8')
const raw = readFileSync(join(DIR, NAME))

// Top-level statements: dollar-quoted bodies, strings and comments are blanked first, so a DO block is one statement.
function topLevelStatements(text: string): string[] {
  return stripSqlNoise(text).text.split(';').map((s) => s.trim().replace(/\s+/g, ' ')).filter((s) => s !== '')
}

describe('migration 13 (onboarding default routine EXECUTE) — file', () => {
  it('has the expected name, is the next number after 12, and the sequence has no gaps or duplicates', () => {
    const { files, invalidNames } = loadMigrationFiles(DIR)
    assert.deepEqual(invalidNames, [])
    assert.deepEqual(files.map((f) => f.version), files.map((_, i) => i + 1))
    assert.equal(files[files.length - 1].filename, NAME)
    assert.equal(files.length, 13)
  })
  it('is LF only (the runner checksums the raw bytes) and ends with a newline', () => {
    assert.equal(raw.includes(13), false)
    assert.equal(raw[raw.length - 1], 10)
  })
  it('passes the runner static scan (no transaction control, no forbidden statements)', () => {
    assert.deepEqual(findForbidden(sql), [])
  })
  it('does not conflict with the recorded history analysis when the earlier files are recorded', () => {
    const { files } = loadMigrationFiles(DIR)
    const history = files.slice(0, 12).map((f) => ({ migration_version: f.version, filename: f.filename, checksum_sha256: f.sha256, adopted: f.version === 1, schema_fingerprint_after: 'x' }))
    const a = analyze(files, [], history)
    assert.deepEqual(a.problems, [])
    assert.deepEqual(a.pending.map((f) => f.filename), [NAME])
  })
})

describe('migration 13 — statements', () => {
  const stmts = topLevelStatements(sql)
  it('is exactly three top-level statements: pre-check DO, the single ALTER DEFAULT PRIVILEGES, post-check DO', () => {
    assert.equal(stmts.length, 3)
    assert.match(stmts[0], /^DO /i) // the dollar-quote tag is blanked by the scan; the order is checked on the raw text below
    assert.equal(stmts[1], MAIN_STATEMENT)
    assert.match(stmts[2], /^DO /i)
    const iPre = sql.indexOf('DO $m13_pre$')
    const iMain = sql.indexOf(`\n${MAIN_STATEMENT};\n`) // a line of its own (the header comment mentions the same text after '-- ')
    const iPost = sql.indexOf('DO $m13_post$')
    assert.ok(iPre >= 0 && iPre < iMain && iMain < iPost)
  })
  it('the only change is the main statement: no GRANT / CREATE / DROP / INSERT / UPDATE / DELETE / SET ROLE / history write outside the check blocks', () => {
    const outside = stmts.filter((s) => !/^DO /i.test(s))
    assert.deepEqual(outside, [MAIN_STATEMENT])
    assert.doesNotMatch(stripSqlNoise(sql).text, /\b(GRANT|CREATE|DROP|INSERT|UPDATE|DELETE|TRUNCATE|SET ROLE|SET SESSION AUTHORIZATION)\b/i)
    assert.doesNotMatch(stripSqlNoise(sql).text, /migration_history/i) // the runner records history; comments may mention it
  })
  it('main statement targets only sobae_onboarding_executor, global (no IN SCHEMA), ROUTINES, REVOKE ... FROM PUBLIC', () => {
    assert.doesNotMatch(MAIN_STATEMENT, /IN SCHEMA|sobae_ops_executor|GRANT/i)
    assert.equal((stripSqlNoise(sql).text.match(/ALTER DEFAULT PRIVILEGES/g) ?? []).length, 1) // comments and DO bodies are blanked: only the one statement remains
    assert.equal(sql.split('\n').filter((l) => l.trim() === MAIN_STATEMENT + ';').length, 1)
  })
})

describe('migration 13 — pre-check content', () => {
  const pre = sql.slice(sql.indexOf('DO $m13_pre$'), sql.indexOf('$m13_pre$;') + 10)
  it('requires current_user = postgres, both roles, effective inheritance (USAGE) — not SET — and zero default ACL rows of any scope', () => {
    assert.match(pre, /current_user <> 'postgres'/)
    assert.match(pre, /to_regrole\('postgres'\) IS NULL OR to_regrole\('sobae_onboarding_executor'\) IS NULL/)
    assert.match(pre, /pg_has_role\(current_user, 'sobae_onboarding_executor', 'USAGE'\)/)
    assert.doesNotMatch(pre, /pg_has_role\([^)]*'SET'\)/)
    assert.match(pre, /FROM pg_default_acl WHERE defaclrole = 'sobae_onboarding_executor'::regrole/)
    assert.doesNotMatch(pre, /defaclnamespace\s*=\s*0/) // counts global and schema-scoped rows alike
    assert.match(pre, /v_n <> 0/)
  })
  it('saves the fingerprints used by the post-check (other default ACLs, routines, console relations, roles and memberships)', () => {
    for (const k of ['others_defacl', 'routines', 'console_relations', 'roles_members']) assert.match(pre, new RegExp(`console_m13\\.${k}`))
  })
})

describe('migration 13 — post-check content', () => {
  const post = sql.slice(sql.indexOf('DO $m13_post$'))
  it('requires exactly one global type-f row whose ACL is the owner only, with no PUBLIC EXECUTE', () => {
    assert.match(post, /v_n <> 1/)
    assert.match(post, /defaclnamespace <> 0 OR r\.defaclobjtype <> 'f'/)
    assert.match(post, /ARRAY\['sobae_onboarding_executor=X\/sobae_onboarding_executor'\]/)
    assert.match(post, /a\.grantee = 0 AND a\.privilege_type = 'EXECUTE'/)
  })
  it('compares every saved fingerprint with the current state', () => {
    for (const k of ['others_defacl', 'routines', 'console_relations', 'roles_members']) assert.match(post, new RegExp(`current_setting\\('console_m13\\.${k}', true\\)`))
  })
})

describe('migration 13 — wording', () => {
  it('states the effect, the managing side, the postgres inheritance caveat and the verify limitation', () => {
    assert.match(sql, /管理主体：Console/)
    assert.match(sql, /実行可能なロールが所有者だけという意味ではない/)
    assert.match(sql, /継承/)
    assert.match(sql, /pg_default_acl と pg_auth_members を含まない/)
    assert.doesNotMatch(sql, /実行できるのは所有者だけ|所有者だけが実行できる/)
  })
})
