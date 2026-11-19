-- =====================================================================
--  ATUALIZAÇÃO 03: backup automático semanal (Google Drive).
--  Um script no Google Drive do administrador chama backup_completo()
--  uma vez por semana, usando um token secreto que só ele conhece.
--  O banco guarda apenas o "hash" do token (não dá para descobrir o token).
--  Para trocar o token: Table Editor > backup_token > apagar a linha,
--  e rodar configurar() de novo no script.
-- =====================================================================
create table if not exists backup_token (
  id         int primary key default 1 check (id = 1),
  token_hash text not null,
  criado_em  timestamptz not null default now()
);
alter table backup_token enable row level security;
revoke all on backup_token from anon, authenticated;

-- Registra o token na primeira configuração (só funciona se ainda não houver um)
create or replace function registrar_token_backup(p_token text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
begin
  if length(coalesce(p_token, '')) < 40 then
    return jsonb_build_object('ok', false, 'erro', 'Token inválido.'); end if;
  if exists (select 1 from backup_token) then
    return jsonb_build_object('ok', false, 'erro', 'Já existe um backup automático registrado. Para trocar, apague a linha da tabela backup_token no Supabase.'); end if;
  insert into backup_token (token_hash) values (crypt(p_token, gen_salt('bf')));
  return jsonb_build_object('ok', true);
end $$;

-- Devolve uma cópia completa do banco (sem os PINs) e registra a data do backup
create or replace function backup_completo(p_token text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare t text;
begin
  select token_hash into t from backup_token where id = 1;
  if t is null or t <> crypt(coalesce(p_token, ''), t) then
    return jsonb_build_object('ok', false, 'erro', 'Token de backup inválido.'); end if;
  insert into config (chave, valor) values ('ultimo_backup', now()::text)
    on conflict (chave) do update set valor = excluded.valor;
  insert into config (chave, valor) values ('ultimo_backup_por', 'Backup automático (Google Drive)')
    on conflict (chave) do update set valor = excluded.valor;
  return jsonb_build_object('ok', true, 'gerado_em', now(),
    'itens',         (select coalesce(jsonb_agg(x order by x.nome), '[]'::jsonb) from itens x),
    'lotes',         (select coalesce(jsonb_agg(x order by x.item_id, x.validade), '[]'::jsonb) from lotes x),
    'movimentacoes', (select coalesce(jsonb_agg(x order by x.id), '[]'::jsonb) from movimentacoes x),
    'usuarios',      (select coalesce(jsonb_agg(jsonb_build_object('id', u.id, 'nome', u.nome, 'papel', u.papel, 'ativo', u.ativo, 'criado_em', u.criado_em) order by u.nome), '[]'::jsonb) from usuarios u),
    'auditoria',     (select coalesce(jsonb_agg(x order by x.id), '[]'::jsonb) from auditoria x),
    'config',        (select coalesce(jsonb_agg(x), '[]'::jsonb) from config x));
end $$;

revoke execute on function registrar_token_backup(text), backup_completo(text) from public;
grant execute on function registrar_token_backup(text), backup_completo(text) to anon, authenticated;
