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
