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
