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
