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
