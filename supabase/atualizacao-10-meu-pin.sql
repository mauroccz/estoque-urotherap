-- =====================================================================
--  ATUALIZAÇÃO 10: cada pessoa altera o próprio PIN
--  (o administrador continua podendo redefinir o PIN de qualquer usuário)
--  Para quem já rodou até a atualização 09: SQL Editor > colar > Run.
-- =====================================================================
set search_path = public, extensions;

create or replace function alterar_meu_pin(p_usuario uuid, p_pin text, p_novo text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare v jsonb;
begin
  v := _checar(p_usuario, p_pin);
  if v is not null then
    if v->>'erro' = 'PIN incorreto.' then return jsonb_build_object('ok', false, 'erro', 'O PIN atual está incorreto.'); end if;
    return v;
  end if;
  if coalesce(p_novo, '') !~ '^\d{4,6}$' then return jsonb_build_object('ok', false, 'erro', 'O novo PIN deve ter de 4 a 6 números.'); end if;
  update usuarios set pin_hash = crypt(p_novo, gen_salt('bf')), falhas = 0, bloqueado_ate = null where id = p_usuario;
  perform _log_usuario(p_usuario, 'pin_alterado');
  return jsonb_build_object('ok', true);
end $$;

grant execute on function alterar_meu_pin(uuid, text, text) to anon, authenticated;
