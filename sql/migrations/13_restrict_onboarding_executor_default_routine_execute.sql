-- 目的：sobae_onboarding_executor が「今後、自分で新規に作成する」関数・プロシージャに、PostgreSQL の既定で付く PUBLIC への EXECUTE を止める（予防）。
--       ALTER DEFAULT PRIVILEGES FOR ROLE sobae_onboarding_executor REVOKE EXECUTE ON ROUTINES FROM PUBLIC;（グローバル）が主文。
-- 作成日：2026-11-24
-- 依存する既存オブジェクト：01_roles.sql（sobae_onboarding_executor）、02_console_schema.sql（console スキーマ）。
--       実行ロールは、Console runner の前提である postgres。postgres が sobae_onboarding_executor の権限を「継承」できること
--       （pg_has_role(current_user, 'sobae_onboarding_executor', 'USAGE')）が必要。SET 権（runner の既存の前提・alter ... owner to 用）とは別の条件。
-- ロールバック方針：適用後に戻す場合は、新しい番号のファイルで
--       `ALTER DEFAULT PRIVILEGES FOR ROLE sobae_onboarding_executor GRANT EXECUTE ON ROUTINES TO PUBLIC;`（pg_default_acl の行が消えることを確認する）。
--       適用後のこのファイルは編集しない（README §5）。このファイルが途中で失敗した場合は、runner が 1 ファイル = 1 トランザクションでロールバックする。
--
-- 管理主体：Console（Console runner・console.migration_history の 1 か所）。本体の Migration・owner-role 登録は変更しない。
--
-- 効くもの：sobae_onboarding_executor 自身が CREATE する、新規の関数・プロシージャ（INVOKER／DEFINER とも）。
--           新しい signature の作成、DROP してからの再作成も、新規作成と同じ（既定が適用される）。
-- 効かないもの：既存ルーチンの ACL は変わらない（default privileges は作成時にだけ参照される）／同じ signature の CREATE OR REPLACE は既存 ACL を維持する／
--           postgres が作成して OWNER を sobae_onboarding_executor へ移したルーチン（現行 runner の関数作成経路。作成時の ACL は作成者 postgres の既定
--           ＝本体 Migration 215 のグローバル既定に従う）／sobae_ops_executor など他のロールの作成物（別件）。
-- 変えないもの：既存 7 関数・2 ビュー・表の定義・所有者・属性・COMMENT・ACL、本体の表・列権限・Policy、他ロール（postgres 等）の default privileges、
--           ロールの属性・membership、業務データ。DROP・GRANT・CREATE は含まない。トップレベルの BEGIN／COMMIT・履歴の INSERT は書かない（runner が行う）。
--
-- この Migration の後の状態：sobae_onboarding_executor が新規に作るルーチンは、明示 GRANT がなければ、直接の付与先が所有者（sobae_onboarding_executor）だけになる。
--   postgres は sobae_onboarding_executor の権限を継承しているため、継承により実行できる（実行可能なロールが所有者だけという意味ではない）。
--   sobae_ops_executor などは、明示 GRANT がなければ実行できない（42501）。必要な呼出しは、従来どおり各 Migration の明示 GRANT で付ける。
--
-- この Migration の中で行う検査（カタログのみ。業務テーブルは読まない）:
--   事前: 実行ロールが postgres／postgres と sobae_onboarding_executor が存在する／postgres が sobae_onboarding_executor を実効継承できる（USAGE）／
--         sobae_onboarding_executor の default privileges が global・schema 別とも 0 行（1 行でもあれば想定外として停止する。自動で上書き・補正しない）。
--         あわせて、他ロールの default privileges・全ルーチンの定義／所有者／ACL／COMMENT・console の表の ACL・role 属性・membership の指紋をセッションへ保存する。
--   事後: sobae_onboarding_executor の default privileges がちょうど 1 行で、グローバル・ROUTINES（type f）・直接の付与先が所有者のみ（PUBLIC・他ロールへの付与なし）／
--         保存した指紋が事前と同一（他ロールの default privileges・既存ルーチン・console の表の ACL・role 属性・membership が不変）。
--   保証しないこと：新規作成物での実際の ACL（隔離 DB の試験で別に確認する）、クラウドの他の既定 ACL、稼働 backend の接続ロール。
--   ※ 通常の verify（console の fingerprint）は pg_default_acl と pg_auth_members を含まない。この Migration の適用前後は、別の READ ONLY 確認で default ACL を確かめる。

DO $m13_pre$
DECLARE
    v_n integer;
BEGIN
    IF current_user <> 'postgres' THEN
        RAISE EXCEPTION '[13] 事前確認: 実行ロールが postgres ではありません（Console runner の前提は postgres）';
    END IF;
    IF to_regrole('postgres') IS NULL OR to_regrole('sobae_onboarding_executor') IS NULL THEN
        RAISE EXCEPTION '[13] 事前確認: ロール postgres または sobae_onboarding_executor が存在しません';
    END IF;
    IF NOT pg_has_role(current_user, 'sobae_onboarding_executor', 'USAGE') THEN
        RAISE EXCEPTION '[13] 事前確認: postgres が sobae_onboarding_executor の権限を継承できません（USAGE なし。SET 権とは別の条件。ALTER DEFAULT PRIVILEGES FOR ROLE には継承が必要）';
    END IF;
    SELECT count(*) INTO v_n FROM pg_default_acl WHERE defaclrole = 'sobae_onboarding_executor'::regrole;
    IF v_n <> 0 THEN
        RAISE EXCEPTION '[13] 事前確認: sobae_onboarding_executor の default privileges が既に % 行あります（global・schema 別を含む。想定は 0 行。内容を確認してから適用してください）', v_n;
    END IF;
    PERFORM set_config('console_m13.others_defacl', (
        SELECT md5(COALESCE(string_agg(pg_get_userbyid(d.defaclrole) || '|' || d.defaclnamespace::text || '|' || d.defaclobjtype::text || '|' || d.defaclacl::text, ',' ORDER BY pg_get_userbyid(d.defaclrole), d.defaclnamespace, d.defaclobjtype), ''))
          FROM pg_default_acl d WHERE d.defaclrole <> 'sobae_onboarding_executor'::regrole), false);
    PERFORM set_config('console_m13.routines', (
        SELECT md5(COALESCE(string_agg(p.oid::regprocedure::text || ':' || md5(to_jsonb(p)::text) || ':' || COALESCE(md5(obj_description(p.oid, 'pg_proc')), '<NULL>'), ',' ORDER BY p.oid::regprocedure::text), ''))
          FROM pg_proc p WHERE p.pronamespace::regnamespace::text NOT IN ('pg_catalog', 'information_schema')), false);
    PERFORM set_config('console_m13.console_relations', (
        SELECT md5(COALESCE(string_agg(c.oid::regclass::text || ':' || c.relkind::text || ':' || c.relowner::regrole::text || ':' || COALESCE(c.relacl::text, 'NULL'), ',' ORDER BY c.oid::regclass::text), ''))
          FROM pg_class c WHERE c.relnamespace = to_regnamespace('console')), false);
    PERFORM set_config('console_m13.roles_members', (
        SELECT md5(
            (SELECT COALESCE(string_agg(r.rolname || ':' || r.rolsuper::text || r.rolinherit::text || r.rolcreaterole::text || r.rolcreatedb::text || r.rolcanlogin::text || r.rolreplication::text || r.rolbypassrls::text || r.rolconnlimit::text, ',' ORDER BY r.rolname), '') FROM pg_roles r WHERE r.rolname !~ '^pg_')
            || '#' ||
            (SELECT COALESCE(string_agg(a.roleid::regrole::text || '>' || a.member::regrole::text || '>' || a.grantor::regrole::text || ':' || a.admin_option::text || a.inherit_option::text || a.set_option::text, ',' ORDER BY a.roleid::regrole::text, a.member::regrole::text, a.grantor::regrole::text), '') FROM pg_auth_members a))), false);
END
$m13_pre$;

ALTER DEFAULT PRIVILEGES FOR ROLE sobae_onboarding_executor REVOKE EXECUTE ON ROUTINES FROM PUBLIC;

DO $m13_post$
DECLARE
    r record;
    v_n integer;
BEGIN
    IF NULLIF(current_setting('console_m13.others_defacl', true), '') IS NULL OR NULLIF(current_setting('console_m13.routines', true), '') IS NULL
       OR NULLIF(current_setting('console_m13.console_relations', true), '') IS NULL OR NULLIF(current_setting('console_m13.roles_members', true), '') IS NULL THEN
        RAISE EXCEPTION '[13] 事後確認: 事前スナップショットがありません（事前確認と同じセッションで実行されていません）';
    END IF;
    SELECT count(*) INTO v_n FROM pg_default_acl WHERE defaclrole = 'sobae_onboarding_executor'::regrole;
    IF v_n <> 1 THEN
        RAISE EXCEPTION '[13] 事後確認: sobae_onboarding_executor の default privileges が % 行です（想定は 1 行）', v_n;
    END IF;
    SELECT d.defaclnamespace, d.defaclobjtype, d.defaclacl INTO r FROM pg_default_acl d WHERE d.defaclrole = 'sobae_onboarding_executor'::regrole;
    IF r.defaclnamespace <> 0 OR r.defaclobjtype <> 'f' THEN
        RAISE EXCEPTION '[13] 事後確認: sobae_onboarding_executor の default privileges がグローバルな ROUTINES ではありません（namespace=%, type=%）', r.defaclnamespace, r.defaclobjtype;
    END IF;
    IF (SELECT array_agg(a::text ORDER BY a::text) FROM unnest(r.defaclacl) AS a) IS DISTINCT FROM ARRAY['sobae_onboarding_executor=X/sobae_onboarding_executor'] THEN
        RAISE EXCEPTION '[13] 事後確認: sobae_onboarding_executor の既定 ACL の直接の付与先が所有者のみ、という想定と異なります（%）', r.defaclacl;
    END IF;
    IF EXISTS (SELECT 1 FROM aclexplode(r.defaclacl) a WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE') THEN
        RAISE EXCEPTION '[13] 事後確認: sobae_onboarding_executor の既定 ACL に PUBLIC の EXECUTE が残っています';
    END IF;
    IF (SELECT md5(COALESCE(string_agg(pg_get_userbyid(d.defaclrole) || '|' || d.defaclnamespace::text || '|' || d.defaclobjtype::text || '|' || d.defaclacl::text, ',' ORDER BY pg_get_userbyid(d.defaclrole), d.defaclnamespace, d.defaclobjtype), ''))
          FROM pg_default_acl d WHERE d.defaclrole <> 'sobae_onboarding_executor'::regrole) IS DISTINCT FROM current_setting('console_m13.others_defacl', true) THEN
        RAISE EXCEPTION '[13] 事後確認: sobae_onboarding_executor 以外の default privileges が変わっています';
    END IF;
    IF (SELECT md5(COALESCE(string_agg(p.oid::regprocedure::text || ':' || md5(to_jsonb(p)::text) || ':' || COALESCE(md5(obj_description(p.oid, 'pg_proc')), '<NULL>'), ',' ORDER BY p.oid::regprocedure::text), ''))
          FROM pg_proc p WHERE p.pronamespace::regnamespace::text NOT IN ('pg_catalog', 'information_schema')) IS DISTINCT FROM current_setting('console_m13.routines', true) THEN
        RAISE EXCEPTION '[13] 事後確認: 既存ルーチンの定義・所有者・ACL・COMMENT のいずれかが変わっています';
    END IF;
    IF (SELECT md5(COALESCE(string_agg(c.oid::regclass::text || ':' || c.relkind::text || ':' || c.relowner::regrole::text || ':' || COALESCE(c.relacl::text, 'NULL'), ',' ORDER BY c.oid::regclass::text), ''))
          FROM pg_class c WHERE c.relnamespace = to_regnamespace('console')) IS DISTINCT FROM current_setting('console_m13.console_relations', true) THEN
        RAISE EXCEPTION '[13] 事後確認: console の表・ビューの所有者または ACL が変わっています';
    END IF;
    IF (SELECT md5(
            (SELECT COALESCE(string_agg(r2.rolname || ':' || r2.rolsuper::text || r2.rolinherit::text || r2.rolcreaterole::text || r2.rolcreatedb::text || r2.rolcanlogin::text || r2.rolreplication::text || r2.rolbypassrls::text || r2.rolconnlimit::text, ',' ORDER BY r2.rolname), '') FROM pg_roles r2 WHERE r2.rolname !~ '^pg_')
            || '#' ||
            (SELECT COALESCE(string_agg(a.roleid::regrole::text || '>' || a.member::regrole::text || '>' || a.grantor::regrole::text || ':' || a.admin_option::text || a.inherit_option::text || a.set_option::text, ',' ORDER BY a.roleid::regrole::text, a.member::regrole::text, a.grantor::regrole::text), '') FROM pg_auth_members a)))
       IS DISTINCT FROM current_setting('console_m13.roles_members', true) THEN
        RAISE EXCEPTION '[13] 事後確認: ロールの属性または membership が変わっています';
    END IF;
END
$m13_post$;
