-- =====================================================================
--  ESTOQUE UROtherap — banco de dados (Supabase / Postgres)
--  Como usar: Supabase > SQL Editor > New query > colar TUDO > Run.
--  Rode uma única vez, num projeto novo.
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;
set search_path = public, extensions;

-- ---------------------------------------------------------------------
-- 1. Tabelas
-- ---------------------------------------------------------------------
create table usuarios (
  id            uuid primary key default gen_random_uuid(),
  nome          text not null unique,
  pin_hash      text not null,
  papel         text not null default 'funcionaria' check (papel in ('admin','funcionaria')),
  ativo         boolean not null default true,
  falhas        int not null default 0,
  bloqueado_ate timestamptz,
  criado_em     timestamptz not null default now()
);

create table itens (
  id             uuid primary key default gen_random_uuid(),
  codigo         text,
  nome           text not null,
  descricao      text,
  categoria      text not null,
  unidade        text,
  local          text,
  cod_fornecedor text,
  fornecedor     text,
  custo_unit     numeric(14,5),
  estoque_minimo numeric not null default 0,
  estoque_ideal  numeric not null default 0,
  controlado     boolean not null default false,
  ativo          boolean not null default true,
  criado_em      timestamptz not null default now()
);

create table lotes (
  id          uuid primary key default gen_random_uuid(),
  item_id     uuid not null references itens(id),
  lote        text,
  fabricacao  date,
  validade    date,
  quantidade  numeric not null default 0 check (quantidade >= 0),
  criado_em   timestamptz not null default now()
);

create table movimentacoes (
  id           bigint generated always as identity primary key,
  item_id      uuid not null references itens(id),
  lote_id      uuid references lotes(id),
  tipo         text not null check (tipo in ('entrada','saida','ajuste','descarte')),
  quantidade   numeric not null,          -- positivo = entrou, negativo = saiu
  saldo_lote   numeric,                   -- saldo do lote depois do registro
  motivo       text,
  usuario_id   uuid references usuarios(id),
  usuario_nome text,
  origem       text not null default 'sistema',  -- sistema | importacao | contingencia
  criado_em    timestamptz not null default now()
);

create table auditoria (
  id           bigint generated always as identity primary key,
  usuario_id   uuid,
  usuario_nome text,
  acao         text,
  tabela       text,
  registro_id  text,
  antes        jsonb,
  depois       jsonb,
  criado_em    timestamptz not null default now()
);

create table config (
  chave text primary key,
  valor text
);

create index on lotes (item_id);
create index on movimentacoes (criado_em desc);
create index on movimentacoes (item_id);
create index on auditoria (criado_em desc);

-- ---------------------------------------------------------------------
-- 2. Auditoria automática (grava quem alterou, o quê e quando)
-- ---------------------------------------------------------------------
create or replace function fn_auditoria() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  v_uid   uuid := nullif(current_setting('app.usuario_id', true), '')::uuid;
  v_nome  text := coalesce(nullif(current_setting('app.usuario_nome', true), ''), 'sistema');
  v_antes jsonb; v_depois jsonb;
begin
  if tg_op = 'UPDATE' and tg_table_name = 'usuarios'
     and (to_jsonb(old) - 'falhas' - 'bloqueado_ate') = (to_jsonb(new) - 'falhas' - 'bloqueado_ate') then
    return new; -- só contador de tentativas de PIN: não audita
  end if;
  if tg_op in ('UPDATE','DELETE') then v_antes  := to_jsonb(old) - 'pin_hash' - 'falhas' - 'bloqueado_ate'; end if;
  if tg_op in ('INSERT','UPDATE') then v_depois := to_jsonb(new) - 'pin_hash' - 'falhas' - 'bloqueado_ate'; end if;
  if tg_op = 'UPDATE' and tg_table_name = 'usuarios' and (to_jsonb(old)->>'pin_hash') is distinct from (to_jsonb(new)->>'pin_hash') then
    v_depois := v_depois || '{"pin":"alterado"}';
  end if;
  insert into auditoria (usuario_id, usuario_nome, acao, tabela, registro_id, antes, depois)
  values (v_uid, v_nome, tg_op, tg_table_name, coalesce(v_depois->>'id', v_antes->>'id'), v_antes, v_depois);
  return coalesce(new, old);
end $$;

create trigger aud_usuarios      after insert or update or delete on usuarios      for each row execute function fn_auditoria();
create trigger aud_itens         after insert or update or delete on itens         for each row execute function fn_auditoria();
create trigger aud_lotes         after insert or update or delete on lotes         for each row execute function fn_auditoria();
create trigger aud_movimentacoes after insert or update or delete on movimentacoes for each row execute function fn_auditoria();

-- Movimentações nunca são editadas nem apagadas
create or replace function fn_bloqueia_alteracao() returns trigger language plpgsql as $$
begin raise exception 'Movimentações não podem ser alteradas. Registre um ajuste.'; end $$;
create trigger mov_imutavel before update or delete on movimentacoes for each row execute function fn_bloqueia_alteracao();

-- ---------------------------------------------------------------------
-- 3. Segurança: leitura liberada para quem tem o link; escrita só por
--    funções que conferem o PIN (o navegador nunca grava direto)
-- ---------------------------------------------------------------------
alter table usuarios      enable row level security;
alter table itens         enable row level security;
alter table lotes         enable row level security;
alter table movimentacoes enable row level security;
alter table auditoria     enable row level security;
alter table config        enable row level security;

create policy leitura on itens         for select to anon, authenticated using (true);
create policy leitura on lotes         for select to anon, authenticated using (true);
create policy leitura on movimentacoes for select to anon, authenticated using (true);
create policy leitura on config        for select to anon, authenticated using (true);

revoke insert, update, delete on all tables in schema public from anon, authenticated;
revoke select on usuarios, auditoria from anon, authenticated;
grant usage on schema public to anon, authenticated;
grant select on itens, lotes, movimentacoes, config to anon, authenticated;

create view usuarios_publicos as select id, nome, papel, ativo from usuarios;
grant select on usuarios_publicos to anon, authenticated;

-- Confere usuário + PIN. Bloqueia 15 min após 5 erros seguidos.
create or replace function _checar(p_usuario uuid, p_pin text, p_admin boolean default false) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare u usuarios;
begin
  select * into u from usuarios where id = p_usuario;
  if not found or not u.ativo then return jsonb_build_object('ok', false, 'erro', 'Usuário inválido ou inativo.'); end if;
  if u.bloqueado_ate is not null and u.bloqueado_ate > now() then
    return jsonb_build_object('ok', false, 'erro', 'Muitas tentativas erradas. Aguarde 15 minutos.');
  end if;
  if u.pin_hash <> crypt(coalesce(p_pin, ''), u.pin_hash) then
    update usuarios set falhas = falhas + 1,
      bloqueado_ate = case when falhas + 1 >= 5 then now() + interval '15 minutes' end
    where id = u.id;
    return jsonb_build_object('ok', false, 'erro', 'PIN incorreto.');
  end if;
  if u.falhas > 0 then update usuarios set falhas = 0, bloqueado_ate = null where id = u.id; end if;
  if p_admin and u.papel <> 'admin' then
    return jsonb_build_object('ok', false, 'erro', 'Apenas administradores podem fazer isso.');
  end if;
  perform set_config('app.usuario_id', u.id::text, true);
  perform set_config('app.usuario_nome', u.nome, true);
  return null;
end $$;

create or replace function entrar(p_usuario uuid, p_pin text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v jsonb; u usuarios;
begin
  v := _checar(p_usuario, p_pin); if v is not null then return v; end if;
  select * into u from usuarios where id = p_usuario;
  return jsonb_build_object('ok', true, 'usuario', jsonb_build_object('id', u.id, 'nome', u.nome, 'papel', u.papel));
end $$;

create or replace function movimentar(p_usuario uuid, p_pin text, p_dados jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v jsonb; l lotes;
  v_tipo text := p_dados->>'tipo';
  v_item uuid := (p_dados->>'item_id')::uuid;
  v_qtd numeric := nullif(p_dados->>'quantidade', '')::numeric;
  v_motivo text := nullif(trim(coalesce(p_dados->>'motivo', '')), '');
  v_delta numeric; v_id bigint;
begin
  v := _checar(p_usuario, p_pin); if v is not null then return v; end if;
  if v_tipo not in ('entrada','saida','ajuste','descarte') then
    return jsonb_build_object('ok', false, 'erro', 'Tipo de movimentação inválido.'); end if;
  if v_qtd is null or v_qtd < 0 or (v_tipo <> 'ajuste' and v_qtd = 0) then
    return jsonb_build_object('ok', false, 'erro', 'Informe uma quantidade válida.'); end if;
  if v_tipo in ('ajuste','descarte') and v_motivo is null then
    return jsonb_build_object('ok', false, 'erro', 'Informe o motivo do ajuste ou descarte.'); end if;

  if v_tipo = 'entrada' and nullif(p_dados->>'lote_id', '') is null then
    insert into lotes (item_id, lote, fabricacao, validade, quantidade)
    values (v_item, nullif(p_dados->>'lote', ''), nullif(p_dados->>'fabricacao', '')::date,
            nullif(p_dados->>'validade', '')::date, 0)
    returning * into l;
  else
    select * into l from lotes where id = (p_dados->>'lote_id')::uuid and item_id = v_item for update;
    if not found then return jsonb_build_object('ok', false, 'erro', 'Lote não encontrado.'); end if;
  end if;

  v_delta := case v_tipo when 'entrada' then v_qtd when 'ajuste' then v_qtd - l.quantidade else -v_qtd end;
  if l.quantidade + v_delta < 0 then
    return jsonb_build_object('ok', false, 'erro', 'Saldo insuficiente no lote (disponível: ' || l.quantidade || ').'); end if;

  update lotes set quantidade = quantidade + v_delta where id = l.id;
  insert into movimentacoes (item_id, lote_id, tipo, quantidade, saldo_lote, motivo, usuario_id, usuario_nome, origem)
  values (v_item, l.id, v_tipo, v_delta, l.quantidade + v_delta, v_motivo, p_usuario,
          current_setting('app.usuario_nome', true), coalesce(nullif(p_dados->>'origem', ''), 'sistema'))
  returning id into v_id;
  return jsonb_build_object('ok', true, 'id', v_id);
end $$;

create or replace function salvar_item(p_usuario uuid, p_pin text, p_item jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v jsonb; v_id uuid := nullif(p_item->>'id', '')::uuid;
begin
  v := _checar(p_usuario, p_pin, true); if v is not null then return v; end if;
  if coalesce(trim(p_item->>'nome'), '') = '' or coalesce(trim(p_item->>'categoria'), '') = '' then
    return jsonb_build_object('ok', false, 'erro', 'Nome e categoria são obrigatórios.'); end if;
  if v_id is null then
    insert into itens (codigo, nome, descricao, categoria, unidade, local, cod_fornecedor, fornecedor, custo_unit,
                       estoque_minimo, estoque_ideal, controlado, ativo)
    values (p_item->>'codigo', p_item->>'nome', p_item->>'descricao', p_item->>'categoria', p_item->>'unidade',
            p_item->>'local', p_item->>'cod_fornecedor', p_item->>'fornecedor', nullif(p_item->>'custo_unit', '')::numeric,
            coalesce(nullif(p_item->>'estoque_minimo', '')::numeric, 0), coalesce(nullif(p_item->>'estoque_ideal', '')::numeric, 0),
            coalesce((p_item->>'controlado')::boolean, false), true)
    returning id into v_id;
  else
    update itens set codigo = p_item->>'codigo', nome = p_item->>'nome', descricao = p_item->>'descricao',
      categoria = p_item->>'categoria', unidade = p_item->>'unidade', local = p_item->>'local',
      cod_fornecedor = p_item->>'cod_fornecedor', fornecedor = p_item->>'fornecedor',
      custo_unit = nullif(p_item->>'custo_unit', '')::numeric,
      estoque_minimo = coalesce(nullif(p_item->>'estoque_minimo', '')::numeric, 0),
      estoque_ideal = coalesce(nullif(p_item->>'estoque_ideal', '')::numeric, 0),
      controlado = coalesce((p_item->>'controlado')::boolean, false),
      ativo = coalesce((p_item->>'ativo')::boolean, true)
    where id = v_id;
  end if;
  return jsonb_build_object('ok', true, 'id', v_id);
end $$;

create or replace function salvar_usuario(p_usuario uuid, p_pin text, p_dados jsonb) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare v jsonb; v_id uuid := nullif(p_dados->>'id', '')::uuid; v_pin text := nullif(p_dados->>'pin', '');
begin
  v := _checar(p_usuario, p_pin, true); if v is not null then return v; end if;
  if v_pin is not null and v_pin !~ '^\d{4}$' then
    return jsonb_build_object('ok', false, 'erro', 'O PIN deve ter 4 números.'); end if;
  if v_id is null then
    if v_pin is null then return jsonb_build_object('ok', false, 'erro', 'Defina um PIN de 4 números.'); end if;
    insert into usuarios (nome, pin_hash, papel)
    values (trim(p_dados->>'nome'), crypt(v_pin, gen_salt('bf')), coalesce(p_dados->>'papel', 'funcionaria'))
    returning id into v_id;
  else
    if v_id = p_usuario and (coalesce((p_dados->>'ativo')::boolean, true) = false or p_dados->>'papel' <> 'admin') then
      return jsonb_build_object('ok', false, 'erro', 'Você não pode desativar nem rebaixar o próprio acesso.'); end if;
    update usuarios set nome = trim(p_dados->>'nome'), papel = coalesce(p_dados->>'papel', papel),
      ativo = coalesce((p_dados->>'ativo')::boolean, ativo),
      pin_hash = case when v_pin is null then pin_hash else crypt(v_pin, gen_salt('bf')) end,
      falhas = 0, bloqueado_ate = null
    where id = v_id;
  end if;
  return jsonb_build_object('ok', true, 'id', v_id);
exception when unique_violation then
  return jsonb_build_object('ok', false, 'erro', 'Já existe um usuário com esse nome.');
end $$;

create or replace function ler_auditoria(p_usuario uuid, p_pin text, p_limite int default 2000) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v jsonb;
begin
  v := _checar(p_usuario, p_pin, true); if v is not null then return v; end if;
  return jsonb_build_object('ok', true, 'dados',
    coalesce((select jsonb_agg(a order by a.id desc) from (select * from auditoria order by id desc limit p_limite) a), '[]'::jsonb));
end $$;

create or replace function registrar_backup(p_usuario uuid, p_pin text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v jsonb;
begin
  v := _checar(p_usuario, p_pin); if v is not null then return v; end if;
  insert into config (chave, valor) values ('ultimo_backup', now()::text)
  on conflict (chave) do update set valor = excluded.valor;
  insert into config (chave, valor) values ('ultimo_backup_por', current_setting('app.usuario_nome', true))
  on conflict (chave) do update set valor = excluded.valor;
  return jsonb_build_object('ok', true);
end $$;

revoke execute on function _checar(uuid, text, boolean) from public, anon, authenticated;
grant execute on function entrar(uuid, text), movimentar(uuid, text, jsonb), salvar_item(uuid, text, jsonb),
  salvar_usuario(uuid, text, jsonb), ler_auditoria(uuid, text, int), registrar_backup(uuid, text) to anon, authenticated;

-- Corrige número, fabricação e validade de um lote (só administrador)
create or replace function salvar_lote(p_usuario uuid, p_pin text, p_lote jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v jsonb;
  v_id  uuid := nullif(p_lote->>'id', '')::uuid;
  v_fab date := nullif(p_lote->>'fabricacao', '')::date;
  v_val date := nullif(p_lote->>'validade', '')::date;
begin
  v := _checar(p_usuario, p_pin, true); if v is not null then return v; end if;
  if v_id is null or not exists (select 1 from lotes where id = v_id) then
    return jsonb_build_object('ok', false, 'erro', 'Lote não encontrado.'); end if;
  if v_fab is not null and v_val is not null and v_val < v_fab then
    return jsonb_build_object('ok', false, 'erro', 'A validade não pode ser anterior à fabricação.'); end if;
  update lotes set lote = nullif(trim(coalesce(p_lote->>'lote', '')), ''), fabricacao = v_fab, validade = v_val
  where id = v_id;
  return jsonb_build_object('ok', true, 'id', v_id);
end $$;

grant execute on function salvar_lote(uuid, text, jsonb) to anon, authenticated;

-- ATUALIZAÇÃO 02: nome do paciente na saída.
alter table movimentacoes add column if not exists paciente text;

-- leitura pública só das colunas sem dado de paciente
revoke select on movimentacoes from anon, authenticated;
grant select (id, item_id, lote_id, tipo, quantidade, saldo_lote, motivo, usuario_id, usuario_nome, origem, criado_em)
  on movimentacoes to anon, authenticated;

create or replace function movimentar(p_usuario uuid, p_pin text, p_dados jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v jsonb; l lotes;
  v_tipo text := p_dados->>'tipo';
  v_item uuid := (p_dados->>'item_id')::uuid;
  v_qtd numeric := nullif(p_dados->>'quantidade', '')::numeric;
  v_motivo text := nullif(trim(coalesce(p_dados->>'motivo', '')), '');
  v_pac text := nullif(trim(coalesce(p_dados->>'paciente', '')), '');
  v_delta numeric; v_id bigint;
begin
  v := _checar(p_usuario, p_pin); if v is not null then return v; end if;
  if v_tipo not in ('entrada','saida','ajuste','descarte') then
    return jsonb_build_object('ok', false, 'erro', 'Tipo de movimentação inválido.'); end if;
  if v_qtd is null or v_qtd < 0 or (v_tipo <> 'ajuste' and v_qtd = 0) then
    return jsonb_build_object('ok', false, 'erro', 'Informe uma quantidade válida.'); end if;
  if v_tipo in ('ajuste','descarte') and v_motivo is null then
    return jsonb_build_object('ok', false, 'erro', 'Informe o motivo do ajuste ou descarte.'); end if;
  if v_tipo <> 'saida' then v_pac := null; end if;

  if v_tipo = 'entrada' and nullif(p_dados->>'lote_id', '') is null then
    insert into lotes (item_id, lote, fabricacao, validade, quantidade)
    values (v_item, nullif(p_dados->>'lote', ''), nullif(p_dados->>'fabricacao', '')::date,
            nullif(p_dados->>'validade', '')::date, 0)
    returning * into l;
  else
    select * into l from lotes where id = (p_dados->>'lote_id')::uuid and item_id = v_item for update;
    if not found then return jsonb_build_object('ok', false, 'erro', 'Lote não encontrado.'); end if;
  end if;

  v_delta := case v_tipo when 'entrada' then v_qtd when 'ajuste' then v_qtd - l.quantidade else -v_qtd end;
  if l.quantidade + v_delta < 0 then
    return jsonb_build_object('ok', false, 'erro', 'Saldo insuficiente no lote (disponível: ' || l.quantidade || ').'); end if;

  update lotes set quantidade = quantidade + v_delta where id = l.id;
  insert into movimentacoes (item_id, lote_id, tipo, quantidade, saldo_lote, motivo, paciente, usuario_id, usuario_nome, origem)
  values (v_item, l.id, v_tipo, v_delta, l.quantidade + v_delta, v_motivo, v_pac, p_usuario,
          current_setting('app.usuario_nome', true), coalesce(nullif(p_dados->>'origem', ''), 'sistema'))
  returning id into v_id;
  return jsonb_build_object('ok', true, 'id', v_id);
end $$;

-- nomes de pacientes: só para quem entrou com nome + PIN
create or replace function ler_pacientes(p_usuario uuid, p_pin text, p_limite int default 20000) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v jsonb;
begin
  v := _checar(p_usuario, p_pin); if v is not null then return v; end if;
  return jsonb_build_object('ok', true, 'dados', coalesce((
    select jsonb_object_agg(id::text, paciente) from (
      select id, paciente from movimentacoes where paciente is not null order by id desc limit p_limite) x), '{}'::jsonb));
end $$;

grant execute on function ler_pacientes(uuid, text, int) to anon, authenticated;

-- ATUALIZAÇÃO 03: backup automático semanal (Google Drive).
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

-- ---------------------------------------------------------------------
-- 4. Primeiro acesso: administrador com PIN 1234 (troque no primeiro uso!)
-- ---------------------------------------------------------------------
insert into usuarios (nome, pin_hash, papel) values ('Administrador', crypt('1234', gen_salt('bf')), 'admin');

-- ---------------------------------------------------------------------
-- 5. Carga inicial: itens e lotes da planilha "Controle_estoque_UROtherap"
-- ---------------------------------------------------------------------
with i as (
  insert into itens (codigo, nome, descricao, categoria, unidade, local, cod_fornecedor, fornecedor, custo_unit)
  values (null, 'COMPRESSA CIRURGICA', 'COMP CAMPO OPERAT EST 25X28CM 20GR C/RX C/DUP EMB (CF)', 'MATERIAL MÉDICO-HOSPITALAR', 'PACOTE', 'ALMOXARIFADO', 'F08662', 'POLARFIX', 8.0805)
  returning id
)
insert into lotes (item_id, lote, fabricacao, validade, quantidade)
select i.id, v.lote, v.fab, v.val, v.qtd from i, (values
    ('092026', '2026-09-01'::date, '2031-08-01'::date, 72)
) as v(lote, fab, val, qtd);

with i as (
  insert into itens (codigo, nome, descricao, categoria, unidade, local, cod_fornecedor, fornecedor, custo_unit)
  values (null, 'POLARBEC 10X15CM', 'COMPRESSA PARA CURATIVO CIRURGICO ESTERIL 10 X 15 CM', 'MATERIAL MÉDICO-HOSPITALAR', 'PACOTE', 'ALMOXARIFADO', 'F08445', 'POLARFIX', 1.12)
  returning id
)
insert into lotes (item_id, lote, fabricacao, validade, quantidade)
select i.id, v.lote, v.fab, v.val, v.qtd from i, (values
    ('092026', '2026-09-01'::date, '2031-08-01'::date, 240)
) as v(lote, fab, val, qtd);

with i as (
  insert into itens (codigo, nome, descricao, categoria, unidade, local, cod_fornecedor, fornecedor, custo_unit)
  values (null, 'POLARBEC 15X30CM', 'COMPRESSA PARA CURATIVO CIRURGICO ESTERIL 15 X 30 CM', 'MATERIAL MÉDICO-HOSPITALAR', 'PACOTE', 'ALMOXARIFADO', 'F08446', 'POLARFIX', 1.56)
  returning id
)
insert into lotes (item_id, lote, fabricacao, validade, quantidade)
select i.id, v.lote, v.fab, v.val, v.qtd from i, (values
    ('092026', '2026-09-01'::date, '2031-08-01'::date, 90)
) as v(lote, fab, val, qtd);

with i as (
  insert into itens (codigo, nome, descricao, categoria, unidade, local, cod_fornecedor, fornecedor, custo_unit)
  values (null, 'MASCARA PROTEÇÃO', 'MASCARA DESC COM ELASTICO TRES CAMADAS', 'EPI', 'UNIDADE', 'ALMOXARIFADO', 'FP0148', 'POLARFIX', 0.03092)
  returning id
)
insert into lotes (item_id, lote, fabricacao, validade, quantidade)
select i.id, v.lote, v.fab, v.val, v.qtd from i, (values
    ('25/0064430000', '2026-01-01'::date, '2031-01-01'::date, 250)
) as v(lote, fab, val, qtd);

with i as (
  insert into itens (codigo, nome, descricao, categoria, unidade, local, cod_fornecedor, fornecedor, custo_unit)
  values (null, 'AVENTAL CIRURGICO', 'AVENTAL CIR EST SMS DESC G RAGLAN M/L C/DUPLA BEM WRAPS + TOALHA', 'MATERIAL MÉDICO-HOSPITALAR', 'UNIDADE', 'ALMOXARIFADO', 'F08386', 'POLARFIX', 20.772)
  returning id
)
insert into lotes (item_id, lote, fabricacao, validade, quantidade)
select i.id, v.lote, v.fab, v.val, v.qtd from i, (values
    ('092026', '2026-09-01'::date, '2031-08-01'::date, 36)
) as v(lote, fab, val, qtd);

with i as (
  insert into itens (codigo, nome, descricao, categoria, unidade, local, cod_fornecedor, fornecedor, custo_unit)
  values (null, 'CAMPO FENESTRADO 1,5 X 2,20', 'CAMPO CIRURGICO EST EM NÃO TECIDO 1,50 X 2,20 M C/ FENESTRA E FITA ADESIVA (LIA)', 'MATERIAL MÉDICO-HOSPITALAR', 'UNIDADE', 'ALMOXARIFADO', 'F08218', 'POLARFIX', 19.4113)
  returning id
)
insert into lotes (item_id, lote, fabricacao, validade, quantidade)
select i.id, v.lote, v.fab, v.val, v.qtd from i, (values
    ('062026', '2026-06-01'::date, '2031-05-01'::date, 24),
    ('64662', '2022-12-02'::date, '2027-12-02'::date, 2),
    ('102025', '2025-10-01'::date, '2030-09-01'::date, 4)
) as v(lote, fab, val, qtd);

with i as (
  insert into itens (codigo, nome, descricao, categoria, unidade, local, cod_fornecedor, fornecedor, custo_unit)
  values (null, 'KIT URO/GINECO/PROCTO', 'KIT CIRURGICO GINECO - URO E PROCTO (GUP) C/ BOLSACOL DE FLUIDOS', 'MATERIAL MÉDICO-HOSPITALAR', 'UNIDADE', 'ALMOXARIFADO', 'F08365', 'POLARFIX', 88.7479)
  returning id
)
insert into lotes (item_id, lote, fabricacao, validade, quantidade)
select i.id, v.lote, v.fab, v.val, v.qtd from i, (values
    ('092026', '2026-09-01'::date, '2031-08-01'::date, 14)
) as v(lote, fab, val, qtd);

with i as (
  insert into itens (codigo, nome, descricao, categoria, unidade, local, cod_fornecedor, fornecedor, custo_unit)
  values (null, 'KIT UNIVERSAL', 'KIT CIRURGICO UNIVERSAL ESTERIL SORBDRAPE (PFX)', 'MATERIAL MÉDICO-HOSPITALAR', 'UNIDADE', 'ALMOXARIFADO', 'F08273', 'POLARFIX', 46.5643)
  returning id
)
insert into lotes (item_id, lote, fabricacao, validade, quantidade)
select i.id, v.lote, v.fab, v.val, v.qtd from i, (values
    ('092026', '2026-09-01'::date, '2031-08-01'::date, 7)
) as v(lote, fab, val, qtd);

with i as (
  insert into itens (codigo, nome, descricao, categoria, unidade, local, cod_fornecedor, fornecedor, custo_unit)
  values (null, 'CAMPO DE MESA', 'CAMPO CIRURGICO EST EM NÃO TECIDO 1,50 M  X 1,93 M LIA', 'MATERIAL MÉDICO-HOSPITALAR', 'UNIDADE', 'ALMOXARIFADO', 'F00208', 'POLARFIX', 9.56)
  returning id
)
insert into lotes (item_id, lote, fabricacao, validade, quantidade)
select i.id, v.lote, v.fab, v.val, v.qtd from i, (values
    ('092026', '2026-09-01'::date, '2031-08-01'::date, 28),
    ('052026', '2026-05-02'::date, '2026-04-02'::date, 12)
) as v(lote, fab, val, qtd);

with i as (
  insert into itens (codigo, nome, descricao, categoria, unidade, local, cod_fornecedor, fornecedor, custo_unit)
  values (null, 'ROPIVACAINA 0,75% (7,5 MG/ML)', 'ROPI 7,5mg/ml sol inj fr 20ml', 'MEDICAÇÃO', 'UNIDADE', 'COFRE CONTROLADO', '70001232', 'CRISTALIA', 21)
  returning id
)
insert into lotes (item_id, lote, fabricacao, validade, quantidade)
select i.id, v.lote, v.fab, v.val, v.qtd from i, (values
    ('50046781', '2026-08-01'::date, '2029-08-01'::date, 10)
) as v(lote, fab, val, qtd);

with i as (
  insert into itens (codigo, nome, descricao, categoria, unidade, local, cod_fornecedor, fornecedor, custo_unit)
  values (null, 'PROPOFOL 1% 20ML', 'PROPOVAN 10mg/ml fr 20ml', 'MEDICAÇÃO', 'UNIDADE', 'COFRE CONTROLADO', '70000070', 'CRISTALIA', 10)
  returning id
)
insert into lotes (item_id, lote, fabricacao, validade, quantidade)
select i.id, v.lote, v.fab, v.val, v.qtd from i, (values
    ('50047185', '2026-09-01'::date, '2028-03-01'::date, 30)
) as v(lote, fab, val, qtd);

with i as (
  insert into itens (codigo, nome, descricao, categoria, unidade, local, cod_fornecedor, fornecedor, custo_unit)
  values (null, 'LIDOCAINA 2% C/ VASO', 'XYLESTESIN 2% CV fr 20ml', 'MEDICAÇÃO', 'UNIDADE', 'COFRE CONTROLADO', '70000105', 'CRISTALIA', 12)
  returning id
)
insert into lotes (item_id, lote, fabricacao, validade, quantidade)
select i.id, v.lote, v.fab, v.val, v.qtd from i, (values
    ('50045266', '2026-07-01'::date, '2028-01-01'::date, 10)
) as v(lote, fab, val, qtd);

with i as (
  insert into itens (codigo, nome, descricao, categoria, unidade, local, cod_fornecedor, fornecedor, custo_unit)
  values (null, 'LIDOCAINA 2% SEM VASO', 'XYLESTESIN 2% SV fr 20ml', 'MEDICAÇÃO', 'UNIDADE', 'COFRE CONTROLADO', '70000106', 'CRISTALIA', 11)
  returning id
)
insert into lotes (item_id, lote, fabricacao, validade, quantidade)
select i.id, v.lote, v.fab, v.val, v.qtd from i, (values
    ('50046379', '2026-08-01'::date, '2029-08-01'::date, 30)
) as v(lote, fab, val, qtd);

with i as (
  insert into itens (codigo, nome, descricao, categoria, unidade, local, cod_fornecedor, fornecedor, custo_unit)
  values (null, 'XYLOCAINA 2% GELEIA', 'XYLESTESIN 2% GELEIA bisnaga 30g', 'MEDICAÇÃO', 'UNIDADE', 'COFRE CONTROLADO', '70000088', 'CRISTALIA', 5)
  returning id
)
insert into lotes (item_id, lote, fabricacao, validade, quantidade)
select i.id, v.lote, v.fab, v.val, v.qtd from i, (values
    ('500044647', '2026-07-01'::date, '2028-07-01'::date, 40)
) as v(lote, fab, val, qtd);

-- Registra a carga inicial como "entrada" de cada lote
insert into movimentacoes (item_id, lote_id, tipo, quantidade, saldo_lote, motivo, usuario_nome, origem)
select item_id, id, 'entrada', quantidade, quantidade, 'Carga inicial da planilha', 'Importação', 'importacao'
from lotes;

-- =====================================================================
--  ATUALIZAÇÃO 04
--   • Código interno por produto (genérico: independe de fornecedor/lote)
--   • Estoque mínimo padrão de 15
--   • Custo dos itens visível só para o administrador
--   • Login digitando o nome (lista de nomes deixa de ser pública), PIN de 4 a 6 números
--   • Listas padrão (cirurgias) e procedimentos com saída automática do estoque
--  Para quem já rodou o schema.sql e as atualizações 01–03: SQL Editor > colar > Run.
-- =====================================================================
set search_path = public, extensions;

-- ---------------------------------------------------------------------
-- 1. Código interno e mínimo padrão
-- ---------------------------------------------------------------------
alter table itens alter column estoque_minimo set default 15;
update itens set estoque_minimo = 15 where coalesce(estoque_minimo, 0) = 0;

update itens set codigo = c.codigo from (values
  ('F08662','MAT-COMPRESSA-25X28'), ('F08445','MAT-CURATIVO-10X15'), ('F08446','MAT-CURATIVO-15X30'),
  ('FP0148','EPI-MASCARA'), ('F08386','MAT-AVENTAL'), ('F08218','MAT-CAMPO-FENEST'), ('F08365','MAT-KIT-UGP'),
  ('F08273','MAT-KIT-UNIV'), ('F00208','MAT-CAMPO-MESA'), ('70001232','MED-ROPIVACAINA-075'), ('70000070','MED-PROPOFOL-1'),
  ('70000105','MED-LIDOCAINA-2CV'), ('70000106','MED-LIDOCAINA-2SV'), ('70000088','MED-LIDOCAINA-GEL2')
) as c(cod_forn, codigo)
where itens.cod_fornecedor = c.cod_forn and coalesce(itens.codigo, '') = '';

create or replace function _codigo_padrao(p_nome text, p_categoria text) returns text
language sql immutable as $$
  select (case when upper(coalesce(p_categoria,'')) like 'MEDICA%' then 'MED'
               when upper(coalesce(p_categoria,'')) like 'EPI%' then 'EPI'
               when upper(coalesce(p_categoria,'')) like 'MATERIAL%' then 'MAT'
               else upper(left(regexp_replace(translate(coalesce(p_categoria,'X'),'ÁÀÂÃÉÊÍÓÔÕÚÇáàâãéêíóôõúç','AAAAEEIOOOUCaaaaeeiooouc'),'[^A-Za-z]','','g'),3)) end)
    || '-' || upper(left(regexp_replace(translate(coalesce(p_nome,''),'ÁÀÂÃÉÊÍÓÔÕÚÇáàâãéêíóôõúç','AAAAEEIOOOUCaaaaeeiooouc'),'[^A-Za-z0-9]+','-','g'),20))
$$;
update itens set codigo = _codigo_padrao(nome, categoria) where coalesce(codigo, '') = '';

create or replace function salvar_item(p_usuario uuid, p_pin text, p_item jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v jsonb; v_id uuid := nullif(p_item->>'id', '')::uuid;
  v_cod text := upper(nullif(trim(coalesce(p_item->>'codigo', '')), ''));
begin
  v := _checar(p_usuario, p_pin, true); if v is not null then return v; end if;
  if coalesce(trim(p_item->>'nome'), '') = '' or coalesce(trim(p_item->>'categoria'), '') = '' then
    return jsonb_build_object('ok', false, 'erro', 'Nome e categoria são obrigatórios.'); end if;
  v_cod := coalesce(v_cod, _codigo_padrao(p_item->>'nome', p_item->>'categoria'));
  if v_id is null then
    insert into itens (codigo, nome, descricao, categoria, unidade, local, cod_fornecedor, fornecedor, custo_unit,
                       estoque_minimo, estoque_ideal, controlado, ativo)
    values (v_cod, p_item->>'nome', p_item->>'descricao', p_item->>'categoria', p_item->>'unidade',
            p_item->>'local', p_item->>'cod_fornecedor', p_item->>'fornecedor', nullif(p_item->>'custo_unit', '')::numeric,
            coalesce(nullif(p_item->>'estoque_minimo', '')::numeric, 15), coalesce(nullif(p_item->>'estoque_ideal', '')::numeric, 0),
            coalesce((p_item->>'controlado')::boolean, false), true)
    returning id into v_id;
  else
    update itens set codigo = v_cod, nome = p_item->>'nome', descricao = p_item->>'descricao',
      categoria = p_item->>'categoria', unidade = p_item->>'unidade', local = p_item->>'local',
      cod_fornecedor = p_item->>'cod_fornecedor', fornecedor = p_item->>'fornecedor',
      custo_unit = case when p_item ? 'custo_unit' then nullif(p_item->>'custo_unit', '')::numeric else custo_unit end,
      estoque_minimo = coalesce(nullif(p_item->>'estoque_minimo', '')::numeric, 15),
      estoque_ideal = coalesce(nullif(p_item->>'estoque_ideal', '')::numeric, 0),
      controlado = coalesce((p_item->>'controlado')::boolean, false),
      ativo = coalesce((p_item->>'ativo')::boolean, true)
    where id = v_id;
  end if;
  return jsonb_build_object('ok', true, 'id', v_id, 'codigo', v_cod);
end $$;

-- ---------------------------------------------------------------------
-- 2. Custo visível só para o administrador
-- ---------------------------------------------------------------------
revoke select on itens from anon, authenticated;
grant select (id, codigo, nome, descricao, categoria, unidade, local, cod_fornecedor, fornecedor,
              estoque_minimo, estoque_ideal, controlado, ativo, criado_em) on itens to anon, authenticated;

create or replace function ler_custos(p_usuario uuid, p_pin text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v jsonb;
begin
  v := _checar(p_usuario, p_pin, true); if v is not null then return v; end if;
  return jsonb_build_object('ok', true, 'dados', coalesce((select jsonb_object_agg(id::text, custo_unit) from itens where custo_unit is not null), '{}'::jsonb));
end $$;

-- ---------------------------------------------------------------------
-- 3. Login digitando o nome; nomes deixam de ficar públicos; PIN de 4 a 6 números
-- ---------------------------------------------------------------------
revoke select on usuarios_publicos from anon, authenticated;

create or replace function _sem_acento(t text) returns text language sql immutable as $$
  select lower(trim(translate(coalesce(t,''), 'ÁÀÂÃÄÉÈÊËÍÌÎÏÓÒÔÕÖÚÙÛÜÇáàâãäéèêëíìîïóòôõöúùûüç', 'AAAAAEEEEIIIIOOOOOUUUUCaaaaaeeeeiiiiooooouuuuc')))
$$;

create or replace function entrar_nome(p_nome text, p_pin text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare u usuarios; v jsonb;
begin
  select * into u from usuarios where _sem_acento(nome) = _sem_acento(p_nome) and ativo limit 1;
  if not found then return jsonb_build_object('ok', false, 'erro', 'Nome ou PIN incorreto.'); end if;
  v := _checar(u.id, p_pin);
  if v is not null then
    if v->>'erro' = 'PIN incorreto.' then return jsonb_build_object('ok', false, 'erro', 'Nome ou PIN incorreto.'); end if;
    return v;
  end if;
  return jsonb_build_object('ok', true, 'usuario', jsonb_build_object('id', u.id, 'nome', u.nome, 'papel', u.papel));
end $$;

create or replace function listar_usuarios(p_usuario uuid, p_pin text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v jsonb;
begin
  v := _checar(p_usuario, p_pin); if v is not null then return v; end if;
  return jsonb_build_object('ok', true, 'dados', coalesce((select jsonb_agg(jsonb_build_object('id', id, 'nome', nome, 'papel', papel, 'ativo', ativo) order by nome) from usuarios), '[]'::jsonb));
end $$;

create or replace function salvar_usuario(p_usuario uuid, p_pin text, p_dados jsonb) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare v jsonb; v_id uuid := nullif(p_dados->>'id', '')::uuid; v_pin text := nullif(p_dados->>'pin', '');
begin
  v := _checar(p_usuario, p_pin, true); if v is not null then return v; end if;
  if v_pin is not null and v_pin !~ '^\d{4,6}$' then
    return jsonb_build_object('ok', false, 'erro', 'O PIN deve ter de 4 a 6 números.'); end if;
  if coalesce(trim(p_dados->>'nome'), '') = '' then return jsonb_build_object('ok', false, 'erro', 'Informe o nome.'); end if;
  if exists (select 1 from usuarios where _sem_acento(nome) = _sem_acento(p_dados->>'nome') and id is distinct from v_id) then
    return jsonb_build_object('ok', false, 'erro', 'Já existe um usuário com esse nome.'); end if;
  if v_id is null then
    if v_pin is null then return jsonb_build_object('ok', false, 'erro', 'Defina um PIN de 4 a 6 números.'); end if;
    insert into usuarios (nome, pin_hash, papel)
    values (trim(p_dados->>'nome'), crypt(v_pin, gen_salt('bf')), coalesce(p_dados->>'papel', 'funcionaria'))
    returning id into v_id;
  else
    if v_id = p_usuario and (coalesce((p_dados->>'ativo')::boolean, true) = false or p_dados->>'papel' <> 'admin') then
      return jsonb_build_object('ok', false, 'erro', 'Você não pode desativar nem rebaixar o próprio acesso.'); end if;
    update usuarios set nome = trim(p_dados->>'nome'), papel = coalesce(p_dados->>'papel', papel),
      ativo = coalesce((p_dados->>'ativo')::boolean, ativo),
      pin_hash = case when v_pin is null then pin_hash else crypt(v_pin, gen_salt('bf')) end,
      falhas = 0, bloqueado_ate = null
    where id = v_id;
  end if;
  return jsonb_build_object('ok', true, 'id', v_id);
exception when unique_violation then
  return jsonb_build_object('ok', false, 'erro', 'Já existe um usuário com esse nome.');
end $$;

-- ---------------------------------------------------------------------
-- 4. Listas padrão (ex.: lista de cada cirurgia)
-- ---------------------------------------------------------------------
create table if not exists listas (
  id              uuid primary key default gen_random_uuid(),
  nome            text not null,
  descricao       text,
  criado_por      uuid references usuarios(id),
  criado_por_nome text,
  ativo           boolean not null default true,
  criado_em       timestamptz not null default now(),
  atualizado_em   timestamptz not null default now()
);
create table if not exists lista_itens (
  id         bigint generated always as identity primary key,
  lista_id   uuid not null references listas(id) on delete cascade,
  item_id    uuid not null references itens(id),
  quantidade numeric not null check (quantidade > 0),
  ordem      int not null default 0
);
create index if not exists lista_itens_lista on lista_itens (lista_id);
alter table listas enable row level security;
alter table lista_itens enable row level security;
drop policy if exists leitura on listas;       create policy leitura on listas      for select to anon, authenticated using (true);
drop policy if exists leitura on lista_itens;  create policy leitura on lista_itens for select to anon, authenticated using (true);
revoke all on listas, lista_itens from anon, authenticated;
grant select on listas, lista_itens to anon, authenticated;
drop trigger if exists aud_listas on listas;
create trigger aud_listas after insert or update or delete on listas for each row execute function fn_auditoria();

create or replace function salvar_lista(p_usuario uuid, p_pin text, p_dados jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v jsonb; v_id uuid := nullif(p_dados->>'id', '')::uuid; l listas; it jsonb; n int := 0;
begin
  v := _checar(p_usuario, p_pin); if v is not null then return v; end if;
  if coalesce(trim(p_dados->>'nome'), '') = '' then return jsonb_build_object('ok', false, 'erro', 'Dê um nome para a lista.'); end if;
  if jsonb_array_length(coalesce(p_dados->'itens', '[]'::jsonb)) = 0 then return jsonb_build_object('ok', false, 'erro', 'Adicione pelo menos um item.'); end if;
  if v_id is null then
    insert into listas (nome, descricao, criado_por, criado_por_nome)
    values (trim(p_dados->>'nome'), nullif(trim(coalesce(p_dados->>'descricao','')), ''), p_usuario, current_setting('app.usuario_nome', true))
    returning id into v_id;
  else
    select * into l from listas where id = v_id and ativo;
    if not found then return jsonb_build_object('ok', false, 'erro', 'Lista não encontrada.'); end if;
    if l.criado_por is distinct from p_usuario then return jsonb_build_object('ok', false, 'erro', 'Só quem criou a lista pode alterá-la. Use "Duplicar" para fazer a sua versão.'); end if;
    update listas set nome = trim(p_dados->>'nome'), descricao = nullif(trim(coalesce(p_dados->>'descricao','')), ''), atualizado_em = now() where id = v_id;
    delete from lista_itens where lista_id = v_id;
  end if;
  for it in select * from jsonb_array_elements(p_dados->'itens') loop
    n := n + 1;
    insert into lista_itens (lista_id, item_id, quantidade, ordem)
    values (v_id, (it->>'item_id')::uuid, (it->>'quantidade')::numeric, n);
  end loop;
  return jsonb_build_object('ok', true, 'id', v_id);
end $$;

create or replace function excluir_lista(p_usuario uuid, p_pin text, p_id uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v jsonb; l listas;
begin
  v := _checar(p_usuario, p_pin); if v is not null then return v; end if;
  select * into l from listas where id = p_id and ativo;
  if not found then return jsonb_build_object('ok', false, 'erro', 'Lista não encontrada.'); end if;
  if l.criado_por is distinct from p_usuario then return jsonb_build_object('ok', false, 'erro', 'Só quem criou a lista pode excluí-la.'); end if;
  update listas set ativo = false, atualizado_em = now() where id = p_id;
  return jsonb_build_object('ok', true);
end $$;

-- ---------------------------------------------------------------------
-- 5. Procedimentos (cirurgias): checagem dos itens e saída do estoque
-- ---------------------------------------------------------------------
create table if not exists procedimentos (
  id                  uuid primary key default gen_random_uuid(),
  lista_id            uuid references listas(id),
  nome                text not null,
  medicos             text,
  anestesistas        text,
  data                date not null default current_date,
  hora_inicio         time,
  hora_fim            time,
  observacoes         text,
  status              text not null default 'aberto' check (status in ('aberto','confirmado','cancelado')),
  criado_por          uuid references usuarios(id),
  criado_por_nome     text,
  confirmado_por_nome text,
  confirmado_em       timestamptz,
  criado_em           timestamptz not null default now(),
  atualizado_em       timestamptz not null default now()
);
create table if not exists procedimento_itens (
  id              bigint generated always as identity primary key,
  procedimento_id uuid not null references procedimentos(id) on delete cascade,
  item_id         uuid not null references itens(id),
  quantidade      numeric not null default 0 check (quantidade >= 0),
  usado           boolean not null default false,
  da_lista        boolean not null default false,
  ordem           int not null default 0,
  lotes_usados    jsonb
);
create index if not exists proc_itens_proc on procedimento_itens (procedimento_id);
create index if not exists proc_data on procedimentos (data desc);
alter table procedimentos enable row level security;
alter table procedimento_itens enable row level security;
revoke all on procedimentos, procedimento_itens from anon, authenticated;
drop trigger if exists aud_procedimentos on procedimentos;
create trigger aud_procedimentos after insert or update or delete on procedimentos for each row execute function fn_auditoria();

create or replace function salvar_procedimento(p_usuario uuid, p_pin text, p_dados jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v jsonb; v_id uuid := nullif(p_dados->>'id', '')::uuid; p procedimentos; it jsonb; n int := 0;
begin
  v := _checar(p_usuario, p_pin); if v is not null then return v; end if;
  if coalesce(trim(p_dados->>'nome'), '') = '' then return jsonb_build_object('ok', false, 'erro', 'Informe o nome do procedimento.'); end if;
  if v_id is null then
    insert into procedimentos (lista_id, nome, medicos, anestesistas, data, hora_inicio, hora_fim, observacoes, criado_por, criado_por_nome)
    values (nullif(p_dados->>'lista_id','')::uuid, trim(p_dados->>'nome'), nullif(trim(coalesce(p_dados->>'medicos','')),''), nullif(trim(coalesce(p_dados->>'anestesistas','')),''),
            coalesce(nullif(p_dados->>'data','')::date, current_date), nullif(p_dados->>'hora_inicio','')::time, nullif(p_dados->>'hora_fim','')::time,
            nullif(trim(coalesce(p_dados->>'observacoes','')),''), p_usuario, current_setting('app.usuario_nome', true))
    returning id into v_id;
  else
    select * into p from procedimentos where id = v_id for update;
    if not found then return jsonb_build_object('ok', false, 'erro', 'Procedimento não encontrado.'); end if;
    if p.status <> 'aberto' then return jsonb_build_object('ok', false, 'erro', 'Este procedimento já foi ' || p.status || ' e não pode ser alterado.'); end if;
    update procedimentos set lista_id = nullif(p_dados->>'lista_id','')::uuid, nome = trim(p_dados->>'nome'),
      medicos = nullif(trim(coalesce(p_dados->>'medicos','')),''), anestesistas = nullif(trim(coalesce(p_dados->>'anestesistas','')),''),
      data = coalesce(nullif(p_dados->>'data','')::date, data), hora_inicio = nullif(p_dados->>'hora_inicio','')::time,
      hora_fim = nullif(p_dados->>'hora_fim','')::time, observacoes = nullif(trim(coalesce(p_dados->>'observacoes','')),''), atualizado_em = now()
    where id = v_id;
    delete from procedimento_itens where procedimento_id = v_id;
  end if;
  for it in select * from jsonb_array_elements(coalesce(p_dados->'itens', '[]'::jsonb)) loop
    n := n + 1;
    insert into procedimento_itens (procedimento_id, item_id, quantidade, usado, da_lista, ordem)
    values (v_id, (it->>'item_id')::uuid, coalesce(nullif(it->>'quantidade','')::numeric, 0), coalesce((it->>'usado')::boolean, false), coalesce((it->>'da_lista')::boolean, false), n);
  end loop;
  return jsonb_build_object('ok', true, 'id', v_id);
end $$;

-- Confirma: dá saída de todos os itens marcados como usados, do lote que vence primeiro (tudo ou nada)
create or replace function confirmar_procedimento(p_usuario uuid, p_pin text, p_id uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v jsonb; p procedimentos; pi record; l record; falta numeric; tira numeric; usados jsonb; i itens; disp numeric;
  v_motivo text; n int := 0;
begin
  v := _checar(p_usuario, p_pin); if v is not null then return v; end if;
  select * into p from procedimentos where id = p_id for update;
  if not found then return jsonb_build_object('ok', false, 'erro', 'Procedimento não encontrado.'); end if;
  if p.status <> 'aberto' then return jsonb_build_object('ok', false, 'erro', 'Este procedimento já foi ' || p.status || '.'); end if;
  if p.hora_fim is null then return jsonb_build_object('ok', false, 'erro', 'Informe o horário de término antes de confirmar.'); end if;
  if not exists (select 1 from procedimento_itens where procedimento_id = p_id and usado and quantidade > 0) then
    return jsonb_build_object('ok', false, 'erro', 'Nenhum item marcado como usado.'); end if;
  v_motivo := left('Procedimento: ' || p.nome || ' · ' || to_char(p.data, 'DD/MM/YYYY'), 200);
  for pi in select * from procedimento_itens where procedimento_id = p_id and usado and quantidade > 0 order by ordem loop
    select * into i from itens where id = pi.item_id;
    select coalesce(sum(quantidade), 0) into disp from lotes where item_id = pi.item_id and quantidade > 0 and (validade is null or validade >= current_date);
    if disp < pi.quantidade then
      raise exception 'Estoque insuficiente de % (disponível sem contar lotes vencidos: %; necessário: %).', i.nome, disp, pi.quantidade;
    end if;
    falta := pi.quantidade; usados := '[]'::jsonb;
    for l in select * from lotes where item_id = pi.item_id and quantidade > 0 and (validade is null or validade >= current_date)
             order by validade nulls last, criado_em for update loop
      exit when falta <= 0;
      tira := least(falta, l.quantidade);
      update lotes set quantidade = quantidade - tira where id = l.id;
      insert into movimentacoes (item_id, lote_id, tipo, quantidade, saldo_lote, motivo, usuario_id, usuario_nome, origem)
      values (pi.item_id, l.id, 'saida', -tira, l.quantidade - tira, v_motivo, p_usuario, current_setting('app.usuario_nome', true), 'procedimento');
      usados := usados || jsonb_build_object('lote', l.lote, 'validade', l.validade, 'quantidade', tira);
      falta := falta - tira; n := n + 1;
    end loop;
    update procedimento_itens set lotes_usados = usados where id = pi.id;
  end loop;
  update procedimentos set status = 'confirmado', confirmado_por_nome = current_setting('app.usuario_nome', true), confirmado_em = now(), atualizado_em = now() where id = p_id;
  return jsonb_build_object('ok', true, 'saidas', n);
exception when raise_exception then
  return jsonb_build_object('ok', false, 'erro', sqlerrm);
end $$;

create or replace function cancelar_procedimento(p_usuario uuid, p_pin text, p_id uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v jsonb;
begin
  v := _checar(p_usuario, p_pin); if v is not null then return v; end if;
  update procedimentos set status = 'cancelado', atualizado_em = now() where id = p_id and status = 'aberto';
  if not found then return jsonb_build_object('ok', false, 'erro', 'Só procedimentos em andamento podem ser cancelados.'); end if;
  return jsonb_build_object('ok', true);
end $$;

create or replace function ler_procedimentos(p_usuario uuid, p_pin text, p_limite int default 300) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v jsonb;
begin
  v := _checar(p_usuario, p_pin); if v is not null then return v; end if;
  return jsonb_build_object('ok', true, 'dados', coalesce((
    select jsonb_agg(to_jsonb(x) || jsonb_build_object('itens', coalesce((
      select jsonb_agg(to_jsonb(pi) order by pi.ordem) from procedimento_itens pi where pi.procedimento_id = x.id), '[]'::jsonb)) order by x.data desc, x.criado_em desc)
    from (select * from procedimentos order by data desc, criado_em desc limit p_limite) x), '[]'::jsonb));
end $$;

-- ---------------------------------------------------------------------
-- 6. Backup automático passa a incluir listas e procedimentos
-- ---------------------------------------------------------------------
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
    'config',        (select coalesce(jsonb_agg(x), '[]'::jsonb) from config x),
    'listas',        (select coalesce(jsonb_agg(x), '[]'::jsonb) from listas x),
    'lista_itens',   (select coalesce(jsonb_agg(x), '[]'::jsonb) from lista_itens x),
    'procedimentos', (select coalesce(jsonb_agg(x), '[]'::jsonb) from procedimentos x),
    'procedimento_itens', (select coalesce(jsonb_agg(x), '[]'::jsonb) from procedimento_itens x));
end $$;

-- ---------------------------------------------------------------------
-- 7. Permissões das funções novas
-- ---------------------------------------------------------------------
revoke execute on function _codigo_padrao(text, text), _sem_acento(text) from public, anon, authenticated;
grant execute on function entrar_nome(text, text), listar_usuarios(uuid, text), ler_custos(uuid, text),
  salvar_lista(uuid, text, jsonb), excluir_lista(uuid, text, uuid),
  salvar_procedimento(uuid, text, jsonb), confirmar_procedimento(uuid, text, uuid),
  cancelar_procedimento(uuid, text, uuid), ler_procedimentos(uuid, text, int) to anon, authenticated;

-- =====================================================================
--  ATUALIZAÇÃO 05
--   • Escolher de qual lote saiu cada material do procedimento
--   • Valor de cada material "congelado" na confirmação (para o documento de reembolso)
--   • Taxas / itens manuais (taxa de sala, RPA etc.) e código do procedimento (TUSS)
--  Para quem já rodou até a atualização 04: SQL Editor > colar > Run.
-- =====================================================================
set search_path = public, extensions;

alter table procedimento_itens add column if not exists lote_id uuid references lotes(id);
alter table procedimento_itens add column if not exists valor_unit numeric;
alter table procedimentos add column if not exists extras jsonb not null default '[]'::jsonb;
alter table procedimentos add column if not exists codigo_procedimento text;

create or replace function _extras_limpos(p jsonb) returns jsonb language sql immutable as $$
  select coalesce(jsonb_agg(jsonb_build_object(
           'descricao', trim(e->>'descricao'),
           'quantidade', coalesce(nullif(e->>'quantidade','')::numeric, 1),
           'valor', nullif(e->>'valor','')::numeric)), '[]'::jsonb)
  from jsonb_array_elements(coalesce(p, '[]'::jsonb)) e
  where coalesce(trim(e->>'descricao'), '') <> ''
$$;

create or replace function salvar_procedimento(p_usuario uuid, p_pin text, p_dados jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v jsonb; v_id uuid := nullif(p_dados->>'id', '')::uuid; p procedimentos; it jsonb; n int := 0;
  v_admin boolean; v_extras jsonb;
begin
  v := _checar(p_usuario, p_pin); if v is not null then return v; end if;
  select papel = 'admin' into v_admin from usuarios where id = p_usuario;
  if coalesce(trim(p_dados->>'nome'), '') = '' then return jsonb_build_object('ok', false, 'erro', 'Informe o nome do procedimento.'); end if;
  v_extras := _extras_limpos(p_dados->'extras');
  if v_id is null then
    insert into procedimentos (lista_id, nome, medicos, anestesistas, data, hora_inicio, hora_fim, observacoes, codigo_procedimento, extras, criado_por, criado_por_nome)
    values (nullif(p_dados->>'lista_id','')::uuid, trim(p_dados->>'nome'), nullif(trim(coalesce(p_dados->>'medicos','')),''), nullif(trim(coalesce(p_dados->>'anestesistas','')),''),
            coalesce(nullif(p_dados->>'data','')::date, current_date), nullif(p_dados->>'hora_inicio','')::time, nullif(p_dados->>'hora_fim','')::time,
            nullif(trim(coalesce(p_dados->>'observacoes','')),''), nullif(trim(coalesce(p_dados->>'codigo_procedimento','')),''),
            case when v_admin then v_extras else (select coalesce(jsonb_agg(e - 'valor'), '[]'::jsonb) from jsonb_array_elements(v_extras) e) end,
            p_usuario, current_setting('app.usuario_nome', true))
    returning id into v_id;
  else
    select * into p from procedimentos where id = v_id for update;
    if not found then return jsonb_build_object('ok', false, 'erro', 'Procedimento não encontrado.'); end if;
    if p.status <> 'aberto' then return jsonb_build_object('ok', false, 'erro', 'Este procedimento já foi ' || p.status || ' e não pode ser alterado.'); end if;
    -- funcionária não vê valores: preserva o valor que o administrador já tiver digitado para a mesma descrição
    if not v_admin then
      v_extras := (select coalesce(jsonb_agg(e || coalesce((select jsonb_build_object('valor', o->'valor') from jsonb_array_elements(p.extras) o
                    where lower(o->>'descricao') = lower(e->>'descricao') limit 1), '{}'::jsonb)), '[]'::jsonb)
                   from jsonb_array_elements(v_extras) e);
    end if;
    update procedimentos set lista_id = nullif(p_dados->>'lista_id','')::uuid, nome = trim(p_dados->>'nome'),
      medicos = nullif(trim(coalesce(p_dados->>'medicos','')),''), anestesistas = nullif(trim(coalesce(p_dados->>'anestesistas','')),''),
      data = coalesce(nullif(p_dados->>'data','')::date, data), hora_inicio = nullif(p_dados->>'hora_inicio','')::time,
      hora_fim = nullif(p_dados->>'hora_fim','')::time, observacoes = nullif(trim(coalesce(p_dados->>'observacoes','')),''),
      codigo_procedimento = nullif(trim(coalesce(p_dados->>'codigo_procedimento','')),''), extras = v_extras, atualizado_em = now()
    where id = v_id;
    delete from procedimento_itens where procedimento_id = v_id;
  end if;
  for it in select * from jsonb_array_elements(coalesce(p_dados->'itens', '[]'::jsonb)) loop
    n := n + 1;
    insert into procedimento_itens (procedimento_id, item_id, quantidade, usado, da_lista, ordem, lote_id)
    values (v_id, (it->>'item_id')::uuid, coalesce(nullif(it->>'quantidade','')::numeric, 0), coalesce((it->>'usado')::boolean, false),
            coalesce((it->>'da_lista')::boolean, false), n, nullif(it->>'lote_id','')::uuid);
  end loop;
  return jsonb_build_object('ok', true, 'id', v_id);
end $$;

create or replace function confirmar_procedimento(p_usuario uuid, p_pin text, p_id uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v jsonb; p procedimentos; pi record; l record; lc lotes; falta numeric; tira numeric; usados jsonb; i itens; disp numeric;
  v_motivo text; n int := 0;
begin
  v := _checar(p_usuario, p_pin); if v is not null then return v; end if;
  select * into p from procedimentos where id = p_id for update;
  if not found then return jsonb_build_object('ok', false, 'erro', 'Procedimento não encontrado.'); end if;
  if p.status <> 'aberto' then return jsonb_build_object('ok', false, 'erro', 'Este procedimento já foi ' || p.status || '.'); end if;
  if p.hora_fim is null then return jsonb_build_object('ok', false, 'erro', 'Informe o horário de término antes de confirmar.'); end if;
  if not exists (select 1 from procedimento_itens where procedimento_id = p_id and usado and quantidade > 0) then
    return jsonb_build_object('ok', false, 'erro', 'Nenhum item marcado como usado.'); end if;
  v_motivo := left('Procedimento: ' || p.nome || ' · ' || to_char(p.data, 'DD/MM/YYYY'), 200);
  for pi in select * from procedimento_itens where procedimento_id = p_id and usado and quantidade > 0 order by ordem loop
    select * into i from itens where id = pi.item_id;
    usados := '[]'::jsonb;
    if pi.lote_id is not null then
      -- lote escolhido manualmente
      select * into lc from lotes where id = pi.lote_id and item_id = pi.item_id for update;
      if not found then raise exception 'O lote escolhido para % não pertence a este item.', i.nome; end if;
      if lc.quantidade < pi.quantidade then
        raise exception 'O lote % de % só tem % em estoque (necessário: %).', coalesce(lc.lote, 's/n'), i.nome, lc.quantidade, pi.quantidade; end if;
      update lotes set quantidade = quantidade - pi.quantidade where id = lc.id;
      insert into movimentacoes (item_id, lote_id, tipo, quantidade, saldo_lote, motivo, usuario_id, usuario_nome, origem)
      values (pi.item_id, lc.id, 'saida', -pi.quantidade, lc.quantidade - pi.quantidade, v_motivo, p_usuario, current_setting('app.usuario_nome', true), 'procedimento');
      usados := jsonb_build_array(jsonb_build_object('lote', lc.lote, 'validade', lc.validade, 'quantidade', pi.quantidade));
      n := n + 1;
    else
      -- automático: lote que vence primeiro
      select coalesce(sum(quantidade), 0) into disp from lotes where item_id = pi.item_id and quantidade > 0 and (validade is null or validade >= current_date);
      if disp < pi.quantidade then
        raise exception 'Estoque insuficiente de % (disponível sem contar lotes vencidos: %; necessário: %).', i.nome, disp, pi.quantidade;
      end if;
      falta := pi.quantidade;
      for l in select * from lotes where item_id = pi.item_id and quantidade > 0 and (validade is null or validade >= current_date)
               order by validade nulls last, criado_em for update loop
        exit when falta <= 0;
        tira := least(falta, l.quantidade);
        update lotes set quantidade = quantidade - tira where id = l.id;
        insert into movimentacoes (item_id, lote_id, tipo, quantidade, saldo_lote, motivo, usuario_id, usuario_nome, origem)
        values (pi.item_id, l.id, 'saida', -tira, l.quantidade - tira, v_motivo, p_usuario, current_setting('app.usuario_nome', true), 'procedimento');
        usados := usados || jsonb_build_object('lote', l.lote, 'validade', l.validade, 'quantidade', tira);
        falta := falta - tira; n := n + 1;
      end loop;
    end if;
    update procedimento_itens set lotes_usados = usados, valor_unit = i.custo_unit where id = pi.id;
  end loop;
  update procedimentos set status = 'confirmado', confirmado_por_nome = current_setting('app.usuario_nome', true), confirmado_em = now(), atualizado_em = now() where id = p_id;
  return jsonb_build_object('ok', true, 'saidas', n);
exception when raise_exception then
  return jsonb_build_object('ok', false, 'erro', sqlerrm);
end $$;

-- Administrador ajusta taxas/itens manuais e valores (também depois de confirmado; não mexe no estoque)
create or replace function salvar_extras_procedimento(p_usuario uuid, p_pin text, p_id uuid, p_extras jsonb, p_valores jsonb default null) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v jsonb; e record;
begin
  v := _checar(p_usuario, p_pin, true); if v is not null then return v; end if;
  update procedimentos set extras = _extras_limpos(p_extras), atualizado_em = now() where id = p_id;
  if not found then return jsonb_build_object('ok', false, 'erro', 'Procedimento não encontrado.'); end if;
  for e in select key, value from jsonb_each(coalesce(p_valores, '{}'::jsonb)) loop
    update procedimento_itens set valor_unit = nullif(e.value #>> '{}', '')::numeric where id = e.key::bigint and procedimento_id = p_id;
  end loop;
  return jsonb_build_object('ok', true);
end $$;

-- Leitura: valores só para o administrador
create or replace function ler_procedimentos(p_usuario uuid, p_pin text, p_limite int default 300) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v jsonb; v_admin boolean;
begin
  v := _checar(p_usuario, p_pin); if v is not null then return v; end if;
  select papel = 'admin' into v_admin from usuarios where id = p_usuario;
  return jsonb_build_object('ok', true, 'dados', coalesce((
    select jsonb_agg(
      (case when v_admin then to_jsonb(x) else (to_jsonb(x) - 'extras') || jsonb_build_object('extras', (select coalesce(jsonb_agg(e - 'valor'), '[]'::jsonb) from jsonb_array_elements(x.extras) e)) end)
      || jsonb_build_object('itens', coalesce((
        select jsonb_agg(case when v_admin then to_jsonb(pi) else to_jsonb(pi) - 'valor_unit' end order by pi.ordem)
        from procedimento_itens pi where pi.procedimento_id = x.id), '[]'::jsonb)) order by x.data desc, x.criado_em desc)
    from (select * from procedimentos order by data desc, criado_em desc limit p_limite) x), '[]'::jsonb));
end $$;

revoke execute on function _extras_limpos(jsonb) from public, anon, authenticated;
grant execute on function salvar_extras_procedimento(uuid, text, uuid, jsonb, jsonb) to anon, authenticated;

-- =====================================================================
--  ATUALIZAÇÃO 06
--   • "Preço para cobrança" por item (só o administrador vê; usado no documento)
--   • Administrador edita o procedimento já confirmado antes de imprimir:
--     cabeçalho, dados do paciente, preços, taxas e materiais
--     (incluir material = saída do estoque; remover = devolve ao mesmo lote)
--  Para quem já rodou até a atualização 05: SQL Editor > colar > Run.
-- =====================================================================
set search_path = public, extensions;

alter table itens add column if not exists preco_cobranca numeric(14,5);
alter table procedimentos add column if not exists paciente_nome text;
alter table procedimentos add column if not exists paciente_cpf text;
alter table procedimentos add column if not exists paciente_convenio text;
alter table procedimentos add column if not exists paciente_carteirinha text;
-- (preco_cobranca fica fora da lista de colunas liberadas para leitura pública)

create or replace function salvar_item(p_usuario uuid, p_pin text, p_item jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v jsonb; v_id uuid := nullif(p_item->>'id', '')::uuid;
  v_cod text := upper(nullif(trim(coalesce(p_item->>'codigo', '')), ''));
begin
  v := _checar(p_usuario, p_pin, true); if v is not null then return v; end if;
  if coalesce(trim(p_item->>'nome'), '') = '' or coalesce(trim(p_item->>'categoria'), '') = '' then
    return jsonb_build_object('ok', false, 'erro', 'Nome e categoria são obrigatórios.'); end if;
  v_cod := coalesce(v_cod, _codigo_padrao(p_item->>'nome', p_item->>'categoria'));
  if v_id is null then
    insert into itens (codigo, nome, descricao, categoria, unidade, local, cod_fornecedor, fornecedor, custo_unit, preco_cobranca,
                       estoque_minimo, estoque_ideal, controlado, ativo)
    values (v_cod, p_item->>'nome', p_item->>'descricao', p_item->>'categoria', p_item->>'unidade',
            p_item->>'local', p_item->>'cod_fornecedor', p_item->>'fornecedor', nullif(p_item->>'custo_unit', '')::numeric,
            nullif(p_item->>'preco_cobranca', '')::numeric,
            coalesce(nullif(p_item->>'estoque_minimo', '')::numeric, 15), coalesce(nullif(p_item->>'estoque_ideal', '')::numeric, 0),
            coalesce((p_item->>'controlado')::boolean, false), true)
    returning id into v_id;
  else
    update itens set codigo = v_cod, nome = p_item->>'nome', descricao = p_item->>'descricao',
      categoria = p_item->>'categoria', unidade = p_item->>'unidade', local = p_item->>'local',
      cod_fornecedor = p_item->>'cod_fornecedor', fornecedor = p_item->>'fornecedor',
      custo_unit = case when p_item ? 'custo_unit' then nullif(p_item->>'custo_unit', '')::numeric else custo_unit end,
      preco_cobranca = case when p_item ? 'preco_cobranca' then nullif(p_item->>'preco_cobranca', '')::numeric else preco_cobranca end,
      estoque_minimo = coalesce(nullif(p_item->>'estoque_minimo', '')::numeric, 15),
      estoque_ideal = coalesce(nullif(p_item->>'estoque_ideal', '')::numeric, 0),
      controlado = coalesce((p_item->>'controlado')::boolean, false),
      ativo = coalesce((p_item->>'ativo')::boolean, true)
    where id = v_id;
  end if;
  return jsonb_build_object('ok', true, 'id', v_id, 'codigo', v_cod);
end $$;

-- custo e preço: só para o administrador
create or replace function ler_custos(p_usuario uuid, p_pin text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v jsonb;
begin
  v := _checar(p_usuario, p_pin, true); if v is not null then return v; end if;
  return jsonb_build_object('ok', true, 'dados', coalesce((select jsonb_object_agg(id::text, jsonb_build_object('c', custo_unit, 'p', preco_cobranca))
    from itens where custo_unit is not null or preco_cobranca is not null), '{}'::jsonb));
end $$;

-- saída de um material (lote escolhido ou o que vence primeiro); devolve os lotes usados
create or replace function _saida_item(p_item uuid, p_qtd numeric, p_lote uuid, p_usuario uuid, p_motivo text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare i itens; lc lotes; l record; falta numeric; tira numeric; usados jsonb := '[]'::jsonb; disp numeric;
begin
  select * into i from itens where id = p_item;
  if not found then raise exception 'Item não encontrado.'; end if;
  if p_lote is not null then
    select * into lc from lotes where id = p_lote and item_id = p_item for update;
    if not found then raise exception 'O lote escolhido para % não pertence a este item.', i.nome; end if;
    if lc.quantidade < p_qtd then
      raise exception 'O lote % de % só tem % em estoque (necessário: %).', coalesce(lc.lote, 's/n'), i.nome, lc.quantidade, p_qtd; end if;
    update lotes set quantidade = quantidade - p_qtd where id = lc.id;
    insert into movimentacoes (item_id, lote_id, tipo, quantidade, saldo_lote, motivo, usuario_id, usuario_nome, origem)
    values (p_item, lc.id, 'saida', -p_qtd, lc.quantidade - p_qtd, p_motivo, p_usuario, current_setting('app.usuario_nome', true), 'procedimento');
    return jsonb_build_array(jsonb_build_object('lote_id', lc.id, 'lote', lc.lote, 'validade', lc.validade, 'quantidade', p_qtd));
  end if;
  select coalesce(sum(quantidade), 0) into disp from lotes where item_id = p_item and quantidade > 0 and (validade is null or validade >= current_date);
  if disp < p_qtd then
    raise exception 'Estoque insuficiente de % (disponível sem contar lotes vencidos: %; necessário: %).', i.nome, disp, p_qtd; end if;
  falta := p_qtd;
  for l in select * from lotes where item_id = p_item and quantidade > 0 and (validade is null or validade >= current_date)
           order by validade nulls last, criado_em for update loop
    exit when falta <= 0;
    tira := least(falta, l.quantidade);
    update lotes set quantidade = quantidade - tira where id = l.id;
    insert into movimentacoes (item_id, lote_id, tipo, quantidade, saldo_lote, motivo, usuario_id, usuario_nome, origem)
    values (p_item, l.id, 'saida', -tira, l.quantidade - tira, p_motivo, p_usuario, current_setting('app.usuario_nome', true), 'procedimento');
    usados := usados || jsonb_build_object('lote_id', l.id, 'lote', l.lote, 'validade', l.validade, 'quantidade', tira);
    falta := falta - tira;
  end loop;
  return usados;
end $$;

create or replace function confirmar_procedimento(p_usuario uuid, p_pin text, p_id uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v jsonb; p procedimentos; pi record; i itens; usados jsonb; v_motivo text; n int := 0;
begin
  v := _checar(p_usuario, p_pin); if v is not null then return v; end if;
  select * into p from procedimentos where id = p_id for update;
  if not found then return jsonb_build_object('ok', false, 'erro', 'Procedimento não encontrado.'); end if;
  if p.status <> 'aberto' then return jsonb_build_object('ok', false, 'erro', 'Este procedimento já foi ' || p.status || '.'); end if;
  if p.hora_fim is null then return jsonb_build_object('ok', false, 'erro', 'Informe o horário de término antes de confirmar.'); end if;
  if not exists (select 1 from procedimento_itens where procedimento_id = p_id and usado and quantidade > 0) then
    return jsonb_build_object('ok', false, 'erro', 'Nenhum item marcado como usado.'); end if;
  v_motivo := left('Procedimento: ' || p.nome || ' · ' || to_char(p.data, 'DD/MM/YYYY'), 200);
  for pi in select * from procedimento_itens where procedimento_id = p_id and usado and quantidade > 0 order by ordem loop
    select * into i from itens where id = pi.item_id;
    usados := _saida_item(pi.item_id, pi.quantidade, pi.lote_id, p_usuario, v_motivo);
    n := n + jsonb_array_length(usados);
    update procedimento_itens set lotes_usados = usados, valor_unit = coalesce(i.preco_cobranca, i.custo_unit) where id = pi.id;
  end loop;
  update procedimentos set status = 'confirmado', confirmado_por_nome = current_setting('app.usuario_nome', true), confirmado_em = now(), atualizado_em = now() where id = p_id;
  return jsonb_build_object('ok', true, 'saidas', n);
exception when raise_exception then
  return jsonb_build_object('ok', false, 'erro', sqlerrm);
end $$;

-- Administrador: dados do documento (não mexe no estoque)
create or replace function editar_procedimento_admin(p_usuario uuid, p_pin text, p_id uuid, p_dados jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v jsonb; p procedimentos; e record;
begin
  v := _checar(p_usuario, p_pin, true); if v is not null then return v; end if;
  select * into p from procedimentos where id = p_id for update;
  if not found then return jsonb_build_object('ok', false, 'erro', 'Procedimento não encontrado.'); end if;
  if p.status <> 'confirmado' then return jsonb_build_object('ok', false, 'erro', 'Só procedimentos confirmados podem ser editados aqui.'); end if;
  if coalesce(trim(p_dados->>'nome'), '') = '' then return jsonb_build_object('ok', false, 'erro', 'Informe o nome do procedimento.'); end if;
  update procedimentos set nome = trim(p_dados->>'nome'),
    codigo_procedimento = nullif(trim(coalesce(p_dados->>'codigo_procedimento','')),''),
    medicos = nullif(trim(coalesce(p_dados->>'medicos','')),''), anestesistas = nullif(trim(coalesce(p_dados->>'anestesistas','')),''),
    data = coalesce(nullif(p_dados->>'data','')::date, data), hora_inicio = nullif(p_dados->>'hora_inicio','')::time, hora_fim = nullif(p_dados->>'hora_fim','')::time,
    observacoes = nullif(trim(coalesce(p_dados->>'observacoes','')),''),
    paciente_nome = nullif(trim(coalesce(p_dados->>'paciente_nome','')),''), paciente_cpf = nullif(trim(coalesce(p_dados->>'paciente_cpf','')),''),
    paciente_convenio = nullif(trim(coalesce(p_dados->>'paciente_convenio','')),''), paciente_carteirinha = nullif(trim(coalesce(p_dados->>'paciente_carteirinha','')),''),
    extras = _extras_limpos(p_dados->'extras'), atualizado_em = now()
  where id = p_id;
  for e in select key, value from jsonb_each(coalesce(p_dados->'valores', '{}'::jsonb)) loop
    update procedimento_itens set valor_unit = nullif(e.value #>> '{}', '')::numeric where id = e.key::bigint and procedimento_id = p_id;
  end loop;
  return jsonb_build_object('ok', true);
end $$;

-- Administrador: incluir material num procedimento confirmado (dá saída do estoque)
create or replace function adicionar_item_procedimento(p_usuario uuid, p_pin text, p_id uuid, p_item uuid, p_qtd numeric, p_lote uuid default null) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v jsonb; p procedimentos; i itens; usados jsonb; v_ordem int;
begin
  v := _checar(p_usuario, p_pin, true); if v is not null then return v; end if;
  select * into p from procedimentos where id = p_id for update;
  if not found or p.status <> 'confirmado' then return jsonb_build_object('ok', false, 'erro', 'Só é possível incluir materiais em procedimentos confirmados.'); end if;
  if coalesce(p_qtd, 0) <= 0 then return jsonb_build_object('ok', false, 'erro', 'Informe a quantidade.'); end if;
  select * into i from itens where id = p_item;
  usados := _saida_item(p_item, p_qtd, p_lote, p_usuario, left('Procedimento: ' || p.nome || ' · ' || to_char(p.data, 'DD/MM/YYYY') || ' (inclusão do administrador)', 200));
  select coalesce(max(ordem), 0) + 1 into v_ordem from procedimento_itens where procedimento_id = p_id;
  insert into procedimento_itens (procedimento_id, item_id, quantidade, usado, da_lista, ordem, lote_id, lotes_usados, valor_unit)
  values (p_id, p_item, p_qtd, true, false, v_ordem, p_lote, usados, coalesce(i.preco_cobranca, i.custo_unit));
  update procedimentos set atualizado_em = now() where id = p_id;
  return jsonb_build_object('ok', true);
exception when raise_exception then
  return jsonb_build_object('ok', false, 'erro', sqlerrm);
end $$;

-- Administrador: remover material de um procedimento confirmado (devolve ao mesmo lote)
create or replace function remover_item_procedimento(p_usuario uuid, p_pin text, p_id uuid, p_linha bigint) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v jsonb; p procedimentos; pi procedimento_itens; e jsonb; lid uuid; l lotes; q numeric; i itens;
begin
  v := _checar(p_usuario, p_pin, true); if v is not null then return v; end if;
  select * into p from procedimentos where id = p_id for update;
  if not found or p.status <> 'confirmado' then return jsonb_build_object('ok', false, 'erro', 'Só é possível remover materiais de procedimentos confirmados.'); end if;
  select * into pi from procedimento_itens where id = p_linha and procedimento_id = p_id for update;
  if not found then return jsonb_build_object('ok', false, 'erro', 'Material não encontrado neste procedimento.'); end if;
  select * into i from itens where id = pi.item_id;
  for e in select * from jsonb_array_elements(coalesce(pi.lotes_usados, '[]'::jsonb)) loop
    q := (e->>'quantidade')::numeric;
    lid := coalesce(nullif(e->>'lote_id','')::uuid, (select id from lotes where item_id = pi.item_id and lote is not distinct from (e->>'lote')
             and validade is not distinct from nullif(e->>'validade','')::date order by criado_em limit 1));
    select * into l from lotes where id = lid for update;
    if not found then raise exception 'Não encontrei o lote % de % para devolver ao estoque.', coalesce(e->>'lote', 's/n'), i.nome; end if;
    update lotes set quantidade = quantidade + q where id = l.id;
    insert into movimentacoes (item_id, lote_id, tipo, quantidade, saldo_lote, motivo, usuario_id, usuario_nome, origem)
    values (pi.item_id, l.id, 'entrada', q, l.quantidade + q,
            left('Estorno: removido do procedimento ' || p.nome || ' · ' || to_char(p.data, 'DD/MM/YYYY'), 200), p_usuario, current_setting('app.usuario_nome', true), 'procedimento');
  end loop;
  delete from procedimento_itens where id = pi.id;
  update procedimentos set atualizado_em = now() where id = p_id;
  return jsonb_build_object('ok', true);
exception when raise_exception then
  return jsonb_build_object('ok', false, 'erro', sqlerrm);
end $$;

-- Leitura: valores e dados do paciente só para o administrador
create or replace function ler_procedimentos(p_usuario uuid, p_pin text, p_limite int default 300) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v jsonb; v_admin boolean;
begin
  v := _checar(p_usuario, p_pin); if v is not null then return v; end if;
  select papel = 'admin' into v_admin from usuarios where id = p_usuario;
  return jsonb_build_object('ok', true, 'dados', coalesce((
    select jsonb_agg(
      (case when v_admin then to_jsonb(x)
            else (to_jsonb(x) - 'extras' - 'paciente_nome' - 'paciente_cpf' - 'paciente_convenio' - 'paciente_carteirinha')
                 || jsonb_build_object('extras', (select coalesce(jsonb_agg(e - 'valor'), '[]'::jsonb) from jsonb_array_elements(x.extras) e)) end)
      || jsonb_build_object('itens', coalesce((
        select jsonb_agg(case when v_admin then to_jsonb(pi) else to_jsonb(pi) - 'valor_unit' end order by pi.ordem)
        from procedimento_itens pi where pi.procedimento_id = x.id), '[]'::jsonb)) order by x.data desc, x.criado_em desc)
    from (select * from procedimentos order by data desc, criado_em desc limit p_limite) x), '[]'::jsonb));
end $$;

revoke execute on function _saida_item(uuid, numeric, uuid, uuid, text) from public, anon, authenticated;
grant execute on function editar_procedimento_admin(uuid, text, uuid, jsonb), adicionar_item_procedimento(uuid, text, uuid, uuid, numeric, uuid),
  remover_item_procedimento(uuid, text, uuid, bigint) to anon, authenticated;

-- =====================================================================
--  ATUALIZAÇÃO 07: preço para cobrança automático = custo + margem padrão (15%)
--  O preço digitado manualmente no item continua valendo; a margem só vale
--  para itens sem preço próprio. O administrador muda a margem no app.
-- =====================================================================
set search_path = public, extensions;

insert into config (chave, valor) values ('margem_cobranca', '15') on conflict (chave) do nothing;

create or replace function _preco_cobranca(p_item uuid) returns numeric
language sql stable security definer set search_path = public as $$
  select coalesce(i.preco_cobranca,
                  round(i.custo_unit * (1 + coalesce((select nullif(valor,'')::numeric from config where chave = 'margem_cobranca'), 15) / 100), 2))
  from itens i where i.id = p_item
$$;

create or replace function confirmar_procedimento(p_usuario uuid, p_pin text, p_id uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v jsonb; p procedimentos; pi record; usados jsonb; v_motivo text; n int := 0;
begin
  v := _checar(p_usuario, p_pin); if v is not null then return v; end if;
  select * into p from procedimentos where id = p_id for update;
  if not found then return jsonb_build_object('ok', false, 'erro', 'Procedimento não encontrado.'); end if;
  if p.status <> 'aberto' then return jsonb_build_object('ok', false, 'erro', 'Este procedimento já foi ' || p.status || '.'); end if;
  if p.hora_fim is null then return jsonb_build_object('ok', false, 'erro', 'Informe o horário de término antes de confirmar.'); end if;
  if not exists (select 1 from procedimento_itens where procedimento_id = p_id and usado and quantidade > 0) then
    return jsonb_build_object('ok', false, 'erro', 'Nenhum item marcado como usado.'); end if;
  v_motivo := left('Procedimento: ' || p.nome || ' · ' || to_char(p.data, 'DD/MM/YYYY'), 200);
  for pi in select * from procedimento_itens where procedimento_id = p_id and usado and quantidade > 0 order by ordem loop
    usados := _saida_item(pi.item_id, pi.quantidade, pi.lote_id, p_usuario, v_motivo);
    n := n + jsonb_array_length(usados);
    update procedimento_itens set lotes_usados = usados, valor_unit = _preco_cobranca(pi.item_id) where id = pi.id;
  end loop;
  update procedimentos set status = 'confirmado', confirmado_por_nome = current_setting('app.usuario_nome', true), confirmado_em = now(), atualizado_em = now() where id = p_id;
  return jsonb_build_object('ok', true, 'saidas', n);
exception when raise_exception then
  return jsonb_build_object('ok', false, 'erro', sqlerrm);
end $$;

create or replace function adicionar_item_procedimento(p_usuario uuid, p_pin text, p_id uuid, p_item uuid, p_qtd numeric, p_lote uuid default null) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v jsonb; p procedimentos; usados jsonb; v_ordem int;
begin
  v := _checar(p_usuario, p_pin, true); if v is not null then return v; end if;
  select * into p from procedimentos where id = p_id for update;
  if not found or p.status <> 'confirmado' then return jsonb_build_object('ok', false, 'erro', 'Só é possível incluir materiais em procedimentos confirmados.'); end if;
  if coalesce(p_qtd, 0) <= 0 then return jsonb_build_object('ok', false, 'erro', 'Informe a quantidade.'); end if;
  usados := _saida_item(p_item, p_qtd, p_lote, p_usuario, left('Procedimento: ' || p.nome || ' · ' || to_char(p.data, 'DD/MM/YYYY') || ' (inclusão do administrador)', 200));
  select coalesce(max(ordem), 0) + 1 into v_ordem from procedimento_itens where procedimento_id = p_id;
  insert into procedimento_itens (procedimento_id, item_id, quantidade, usado, da_lista, ordem, lote_id, lotes_usados, valor_unit)
  values (p_id, p_item, p_qtd, true, false, v_ordem, p_lote, usados, _preco_cobranca(p_item));
  update procedimentos set atualizado_em = now() where id = p_id;
  return jsonb_build_object('ok', true);
exception when raise_exception then
  return jsonb_build_object('ok', false, 'erro', sqlerrm);
end $$;

-- Administrador altera configurações (por enquanto: margem padrão de cobrança)
create or replace function salvar_config(p_usuario uuid, p_pin text, p_chave text, p_valor text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v jsonb;
begin
  v := _checar(p_usuario, p_pin, true); if v is not null then return v; end if;
  if p_chave not in ('margem_cobranca') then return jsonb_build_object('ok', false, 'erro', 'Configuração desconhecida.'); end if;
  if p_chave = 'margem_cobranca' and (p_valor !~ '^\d{1,3}([.,]\d{1,2})?$') then
    return jsonb_build_object('ok', false, 'erro', 'Informe a margem em %, por exemplo 15.'); end if;
  insert into config (chave, valor) values (p_chave, replace(p_valor, ',', '.'))
    on conflict (chave) do update set valor = excluded.valor;
  return jsonb_build_object('ok', true);
end $$;

revoke execute on function _preco_cobranca(uuid) from public, anon, authenticated;
grant execute on function salvar_config(uuid, text, text, text) to anon, authenticated;

-- Pronto. Próximo passo: copiar a URL e a anon key (Project Settings > API) para o arquivo config.js.


-- =====================================================================
--  ATUALIZAÇÃO 08: códigos dos produtos no padrão simples
--   PREFIXO-NOME APRESENTAÇÃO  (ex.: MED-PROPOFOL 1%, MED-ROPIVACAINA 0,75%)
--   Produtos equivalentes (fornecedores/lotes diferentes) usam o MESMO código.
--  Para quem já rodou até a atualização 07: SQL Editor > colar > Run.
-- =====================================================================
set search_path = public, extensions;

-- código sugerido pelo servidor quando o app não envia nenhum
create or replace function _codigo_padrao(p_nome text, p_categoria text) returns text
language sql immutable as $$
  with n as (select upper(translate(coalesce(p_nome,''),'ÁÀÂÃÉÊÍÓÔÕÚÇáàâãéêíóôõúç','AAAAEEIOOOUCaaaaeeiooouc')) as nome)
  select left(
    (case when upper(coalesce(p_categoria,'')) like 'MEDICA%' then 'MED'
          when upper(coalesce(p_categoria,'')) like 'EPI%' then 'EPI'
          when upper(coalesce(p_categoria,'')) like 'MATERIAL%' then 'MAT'
          else coalesce(nullif(upper(left(regexp_replace(translate(coalesce(p_categoria,''),'ÁÀÂÃÉÊÍÓÔÕÚÇáàâãéêíóôõúç','AAAAEEIOOOUCaaaaeeiooouc'),'[^A-Za-z]','','g'),3)),''),'ITM') end)
    || '-' || coalesce((regexp_match(n.nome, '([A-Z]{2,})'))[1], 'ITEM')
    || coalesce(' ' || (regexp_match(n.nome, '(?:^|\s)([0-9][0-9A-Z,.%/]*)'))[1], ''), 40)
  from n
$$;

-- códigos atuais → padrão novo (Propofol e Ropivacaína já estavam no padrão)
update itens set codigo = x.novo
from (values
  ('MAT-CAMPO-FENEST',         'MAT-CAMPO FENESTRADO'),
  ('MAT-CAMPO-MESA',           'MAT-CAMPO MESA'),
  ('MAT-COLETOR-URINA-CAMA-M', 'MAT-COLETOR URINA'),
  ('MAT-COMPRESSA-25X28',      'MAT-COMPRESSA 25X28'),
  ('MAT-CURATIVO-10X15',       'MAT-CURATIVO 10X15'),
  ('MAT-CURATIVO-15X30',       'MAT-CURATIVO 15X30'),
  ('MAT-EQUIPO-2-VIAS-POLIFI', 'MAT-EQUIPO 2 VIAS'),
  ('MAT-EQUIPO-MACRO-C-INJET', 'MAT-EQUIPO MACRO'),
  ('MAT-KIT-UGP',              'MAT-KIT UGP'),
  ('MAT-KIT-UNIV',             'MAT-KIT UNIVERSAL'),
  ('MAT-SONDA-FOLEY-18-MEDIX', 'MAT-SONDA FOLEY 18'),
  ('MED-KETAMIN-50MG',         'MED-CETAMINA 50MG/ML'),
  ('MED-LIDOCAINA-2CV',        'MED-LIDOCAINA 2% C/V'),
  ('MED-LIDOCAINA-2SV',        'MED-LIDOCAINA 2% S/V'),
  ('MED-LIDOCAINA-GEL2',       'MED-LIDOCAINA 2% GEL'),
  ('MED-SEVOCRIS-100',         'MED-SEVOFLURANO 100%'),
  ('MED-PROPOFOL-1',           'MED-PROPOFOL 1%'),
  ('MED-ROPIVACAINA-075',      'MED-ROPIVACAINA 0,75%')
) as x(antigo, novo)
where itens.codigo = x.antigo;


-- =====================================================================
--  ATUALIZAÇÃO 09
--   • Toda a equipe cadastra e corrige itens e lotes (inclusive pela NF).
--     Custo e preço para cobrança continuam só com o administrador.
--   • Usuários: nome completo, função, histórico de bloqueios;
--     administrador bloqueia, desbloqueia, exclui e redefine o PIN.
--     Excluir não apaga nada do histórico: o nome continua nos registros.
--  Para quem já rodou até a atualização 08: SQL Editor > colar > Run.
-- =====================================================================
set search_path = public, extensions;

alter table usuarios add column if not exists nome_completo text;
alter table usuarios add column if not exists funcao text;
alter table usuarios add column if not exists excluido boolean not null default false;
alter table usuarios add column if not exists excluido_em timestamptz;
alter table usuarios add column if not exists historico jsonb not null default '[]'::jsonb;

create or replace function _log_usuario(p_id uuid, p_acao text) returns void
language sql security definer set search_path = public as $$
  update usuarios set historico = historico || jsonb_build_array(jsonb_build_object(
    'acao', p_acao, 'em', now(), 'por', current_setting('app.usuario_nome', true)))
  where id = p_id;
$$;

-- ---------- itens: qualquer usuário cadastra/edita; custo e preço só o administrador ----------
create or replace function salvar_item(p_usuario uuid, p_pin text, p_item jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v jsonb; v_id uuid := nullif(p_item->>'id', '')::uuid; v_admin boolean;
  v_cod text := upper(nullif(trim(coalesce(p_item->>'codigo', '')), ''));
begin
  v := _checar(p_usuario, p_pin); if v is not null then return v; end if;
  select papel = 'admin' into v_admin from usuarios where id = p_usuario;
  if not v_admin then
    p_item := p_item - 'preco_cobranca';                       -- preço: só o administrador
    if v_id is not null then p_item := p_item - 'custo_unit'; end if;  -- custo: só no cadastro (ex.: vindo da NF)
  end if;
  if coalesce(trim(p_item->>'nome'), '') = '' or coalesce(trim(p_item->>'categoria'), '') = '' then
    return jsonb_build_object('ok', false, 'erro', 'Nome e categoria são obrigatórios.'); end if;
  v_cod := coalesce(v_cod, _codigo_padrao(p_item->>'nome', p_item->>'categoria'));
  if v_id is null then
    insert into itens (codigo, nome, descricao, categoria, unidade, local, cod_fornecedor, fornecedor, custo_unit, preco_cobranca,
                       estoque_minimo, estoque_ideal, controlado, ativo)
    values (v_cod, p_item->>'nome', p_item->>'descricao', p_item->>'categoria', p_item->>'unidade',
            p_item->>'local', p_item->>'cod_fornecedor', p_item->>'fornecedor', nullif(p_item->>'custo_unit', '')::numeric,
            nullif(p_item->>'preco_cobranca', '')::numeric,
            coalesce(nullif(p_item->>'estoque_minimo', '')::numeric, 15), coalesce(nullif(p_item->>'estoque_ideal', '')::numeric, 0),
            coalesce((p_item->>'controlado')::boolean, false), true)
    returning id into v_id;
  else
    update itens set codigo = v_cod, nome = p_item->>'nome', descricao = p_item->>'descricao',
      categoria = p_item->>'categoria', unidade = p_item->>'unidade', local = p_item->>'local',
      cod_fornecedor = p_item->>'cod_fornecedor', fornecedor = p_item->>'fornecedor',
      custo_unit = case when p_item ? 'custo_unit' then nullif(p_item->>'custo_unit', '')::numeric else custo_unit end,
      preco_cobranca = case when p_item ? 'preco_cobranca' then nullif(p_item->>'preco_cobranca', '')::numeric else preco_cobranca end,
      estoque_minimo = coalesce(nullif(p_item->>'estoque_minimo', '')::numeric, 15),
      estoque_ideal = coalesce(nullif(p_item->>'estoque_ideal', '')::numeric, 0),
      controlado = coalesce((p_item->>'controlado')::boolean, false),
      ativo = coalesce((p_item->>'ativo')::boolean, true)
    where id = v_id;
  end if;
  return jsonb_build_object('ok', true, 'id', v_id, 'codigo', v_cod);
end $$;

-- ---------- lotes: qualquer usuário corrige número, fabricação e validade ----------
create or replace function salvar_lote(p_usuario uuid, p_pin text, p_lote jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v jsonb;
  v_id  uuid := nullif(p_lote->>'id', '')::uuid;
  v_fab date := nullif(p_lote->>'fabricacao', '')::date;
  v_val date := nullif(p_lote->>'validade', '')::date;
begin
  v := _checar(p_usuario, p_pin); if v is not null then return v; end if;
  if v_id is null or not exists (select 1 from lotes where id = v_id) then
    return jsonb_build_object('ok', false, 'erro', 'Lote não encontrado.'); end if;
  if v_fab is not null and v_val is not null and v_val < v_fab then
    return jsonb_build_object('ok', false, 'erro', 'A validade não pode ser anterior à fabricação.'); end if;
  update lotes set lote = nullif(trim(coalesce(p_lote->>'lote', '')), ''), fabricacao = v_fab, validade = v_val
  where id = v_id;
  return jsonb_build_object('ok', true, 'id', v_id);
end $$;

-- ---------- login: acesso bloqueado ou excluído não entra ----------
create or replace function entrar_nome(p_nome text, p_pin text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare u usuarios; v jsonb;
begin
  select * into u from usuarios where _sem_acento(nome) = _sem_acento(p_nome) and not excluido limit 1;
  if not found then return jsonb_build_object('ok', false, 'erro', 'Nome ou PIN incorreto.'); end if;
  if not u.ativo then
    if u.pin_hash = crypt(coalesce(p_pin, ''), u.pin_hash) then
      return jsonb_build_object('ok', false, 'erro', 'Este acesso está bloqueado. Fale com o administrador.'); end if;
    return jsonb_build_object('ok', false, 'erro', 'Nome ou PIN incorreto.');
  end if;
  v := _checar(u.id, p_pin);
  if v is not null then
    if v->>'erro' = 'PIN incorreto.' then return jsonb_build_object('ok', false, 'erro', 'Nome ou PIN incorreto.'); end if;
    return v;
  end if;
  return jsonb_build_object('ok', true, 'usuario', jsonb_build_object('id', u.id, 'nome', u.nome, 'papel', u.papel));
end $$;

-- ---------- lista de usuários: dados completos só para o administrador ----------
create or replace function listar_usuarios(p_usuario uuid, p_pin text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v jsonb; v_admin boolean;
begin
  v := _checar(p_usuario, p_pin); if v is not null then return v; end if;
  select papel = 'admin' into v_admin from usuarios where id = p_usuario;
  return jsonb_build_object('ok', true, 'dados', coalesce((select jsonb_agg(
    case when v_admin then jsonb_build_object('id', id, 'nome', nome, 'papel', papel, 'ativo', ativo, 'excluido', excluido,
           'excluido_em', excluido_em, 'nome_completo', nome_completo, 'funcao', funcao, 'criado_em', criado_em, 'historico', historico)
         else jsonb_build_object('id', id, 'nome', nome, 'papel', papel, 'ativo', ativo) end order by nome)
    from usuarios where v_admin or not excluido), '[]'::jsonb));
end $$;

-- ---------- criar / editar usuário (admin) ----------
create or replace function salvar_usuario(p_usuario uuid, p_pin text, p_dados jsonb) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare v jsonb; v_id uuid := nullif(p_dados->>'id', '')::uuid; v_pin text := nullif(p_dados->>'pin', ''); u usuarios;
  v_ativo boolean;
begin
  v := _checar(p_usuario, p_pin, true); if v is not null then return v; end if;
  if v_pin is not null and v_pin !~ '^\d{4,6}$' then
    return jsonb_build_object('ok', false, 'erro', 'O PIN deve ter de 4 a 6 números.'); end if;
  if coalesce(trim(p_dados->>'nome'), '') = '' then return jsonb_build_object('ok', false, 'erro', 'Informe o nome de login.'); end if;
  if exists (select 1 from usuarios where _sem_acento(nome) = _sem_acento(p_dados->>'nome') and id is distinct from v_id) then
    return jsonb_build_object('ok', false, 'erro', 'Já existe um usuário com esse nome de login (pode ser um login excluído).'); end if;
  if v_id is null then
    if v_pin is null then return jsonb_build_object('ok', false, 'erro', 'Defina um PIN de 4 a 6 números.'); end if;
    insert into usuarios (nome, pin_hash, papel, nome_completo, funcao)
    values (trim(p_dados->>'nome'), crypt(v_pin, gen_salt('bf')), coalesce(p_dados->>'papel', 'funcionaria'),
            nullif(trim(coalesce(p_dados->>'nome_completo','')),''), nullif(trim(coalesce(p_dados->>'funcao','')),''))
    returning id into v_id;
    perform _log_usuario(v_id, 'criado');
  else
    select * into u from usuarios where id = v_id for update;
    if not found or u.excluido then return jsonb_build_object('ok', false, 'erro', 'Usuário não encontrado.'); end if;
    v_ativo := coalesce((p_dados->>'ativo')::boolean, u.ativo);
    if v_id = p_usuario and (v_ativo = false or coalesce(p_dados->>'papel', u.papel) <> 'admin') then
      return jsonb_build_object('ok', false, 'erro', 'Você não pode bloquear nem rebaixar o próprio acesso.'); end if;
    update usuarios set nome = trim(p_dados->>'nome'), papel = coalesce(p_dados->>'papel', papel), ativo = v_ativo,
      nome_completo = case when p_dados ? 'nome_completo' then nullif(trim(coalesce(p_dados->>'nome_completo','')),'') else nome_completo end,
      funcao = case when p_dados ? 'funcao' then nullif(trim(coalesce(p_dados->>'funcao','')),'') else funcao end,
      pin_hash = case when v_pin is null then pin_hash else crypt(v_pin, gen_salt('bf')) end,
      falhas = 0, bloqueado_ate = null
    where id = v_id;
    if v_ativo <> u.ativo then perform _log_usuario(v_id, case when v_ativo then 'desbloqueado' else 'bloqueado' end); end if;
    if v_pin is not null then perform _log_usuario(v_id, 'pin_redefinido'); end if;
  end if;
  return jsonb_build_object('ok', true, 'id', v_id);
exception when unique_violation then
  return jsonb_build_object('ok', false, 'erro', 'Já existe um usuário com esse nome de login.');
end $$;

-- ---------- excluir login (admin): o histórico continua com o nome ----------
create or replace function excluir_usuario(p_usuario uuid, p_pin text, p_id uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare v jsonb;
begin
  v := _checar(p_usuario, p_pin, true); if v is not null then return v; end if;
  if p_id = p_usuario then return jsonb_build_object('ok', false, 'erro', 'Você não pode excluir o próprio acesso.'); end if;
  update usuarios set excluido = true, excluido_em = now(), ativo = false where id = p_id and not excluido;
  if not found then return jsonb_build_object('ok', false, 'erro', 'Usuário não encontrado.'); end if;
  perform _log_usuario(p_id, 'excluido');
  return jsonb_build_object('ok', true);
end $$;

revoke execute on function _log_usuario(uuid, text) from public, anon, authenticated;
grant execute on function excluir_usuario(uuid, text, uuid) to anon, authenticated;
