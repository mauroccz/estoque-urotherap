-- =====================================================================
--  ATUALIZAÇÃO 02: nome do paciente na saída.
--  O nome do paciente é dado de saúde (LGPD): a coluna NÃO fica visível
--  para quem só tem o link; só é lida por quem entra com nome + PIN.
--  Para quem já rodou o schema.sql: Supabase > SQL Editor > colar > Run.
-- =====================================================================
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
