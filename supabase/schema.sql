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

-- Pronto. Próximo passo: copiar a URL e a anon key (Project Settings > API) para o arquivo config.js.
