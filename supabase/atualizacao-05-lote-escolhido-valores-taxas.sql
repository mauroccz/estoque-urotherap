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
