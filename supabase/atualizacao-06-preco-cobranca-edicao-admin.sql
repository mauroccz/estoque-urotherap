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
