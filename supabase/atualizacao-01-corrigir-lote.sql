-- =====================================================================
--  ATUALIZAÇÃO 01: permite ao administrador corrigir número do lote,
--  fabricação e validade de um lote já cadastrado.
--  Para quem já rodou o schema.sql: Supabase > SQL Editor > colar > Run.
--  A alteração fica registrada na auditoria (antes → depois).
-- =====================================================================
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
