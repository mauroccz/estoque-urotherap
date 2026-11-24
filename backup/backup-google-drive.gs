/**
 * BACKUP SEMANAL AUTOMÁTICO — Estoque UROtherap
 * Roda no Google Apps Script da conta Google do administrador.
 * Toda segunda-feira, entre 6h e 7h, salva na pasta "Backup Estoque UROtherap" do Drive,
 * separado em pastas por ano e mês (ex.: Backup Estoque UROtherap / 2026 / 11 - Novembro):
 *   • estoque-urotherap-backup-AAAA-MM-DD.xlsx  → para abrir e conferir (Excel / Planilhas)
 *   • estoque-urotherap-backup-AAAA-MM-DD.json  → cópia completa e exata, para restaurar o banco
 *
 * Para organizar os backups antigos (que estão soltos na pasta principal) nas pastas de ano e mês:
 * escolha "organizarBackupsAntigos" e clique em Executar (só precisa uma vez).
 * Primeira vez: escolha a função "configurar" no menu acima e clique em Executar.
 * Para testar a qualquer momento: escolha "fazerBackup" e clique em Executar.
 * Se um backup falhar, o Google manda um e-mail automático avisando.
 */

const SITE  = 'https://urotherap-clinica.github.io/estoque-urotherap/';
const PASTA = 'Backup Estoque UROtherap';
const FUSO  = 'America/Sao_Paulo';
const MESES = ['Janeiro', 'Fevereiro', 'Março', 'Abril', 'Maio', 'Junho', 'Julho', 'Agosto', 'Setembro', 'Outubro', 'Novembro', 'Dezembro'];
const TIPOS = { entrada: 'Entrada', saida: 'Saída', ajuste: 'Ajuste', descarte: 'Descarte' };

/** Rode uma vez: cria o token secreto, a pasta, o agendamento semanal e já faz o primeiro backup. */
function configurar() {
  const props = PropertiesService.getScriptProperties();
  let token = props.getProperty('TOKEN');
  if (!token) {
    token = Utilities.getUuid().replace(/-/g, '') + Utilities.getUuid().replace(/-/g, '');
    const r = rpc_('registrar_token_backup', { p_token: token });
    if (!r.ok) throw new Error(r.erro);
    props.setProperty('TOKEN', token);
  }
  ScriptApp.getProjectTriggers()
    .filter(t => t.getHandlerFunction() === 'fazerBackup')
    .forEach(t => ScriptApp.deleteTrigger(t));
  ScriptApp.newTrigger('fazerBackup').timeBased()
    .onWeekDay(ScriptApp.WeekDay.MONDAY).atHour(6).inTimezone(FUSO).create();
  pasta_();
  fazerBackup();
  Logger.log('Pronto! Backup semanal agendado para toda segunda-feira, entre 6h e 7h.');
}

/** Faz um backup agora. */
function fazerBackup() {
  const token = PropertiesService.getScriptProperties().getProperty('TOKEN');
  if (!token) throw new Error('Rode a função configurar() primeiro.');
  const d = rpc_('backup_completo', { p_token: token });
  if (!d.ok) throw new Error(d.erro || 'O banco recusou o backup.');

  const agora = new Date();
  const nome = 'estoque-urotherap-backup-' + Utilities.formatDate(agora, FUSO, "yyyy-MM-dd_HH'h'mm");
  const pasta = pastaDoMes_(agora);

  // 1) Cópia completa (JSON)
  pasta.createFile(Utilities.newBlob(JSON.stringify(d, null, 1), 'application/json', nome + '.json'));

  // 2) Planilha para conferência (XLSX)
  const idx = {}; d.itens.forEach(i => idx[i.id] = i);
  const lotesIdx = {}; d.lotes.forEach(l => lotesIdx[l.id] = l);
  const saldo = {}; d.lotes.forEach(l => saldo[l.item_id] = (saldo[l.item_id] || 0) + Number(l.quantidade));

  const ss = SpreadsheetApp.create(nome);
  let primeira = true;
  const aba = (titulo, cab, linhas) => {
    const sh = primeira ? ss.getSheets()[0].setName(titulo) : ss.insertSheet(titulo);
    primeira = false;
    const dados = [cab].concat(linhas.map(r => r.map(txt_)));
    sh.getRange(1, 1, dados.length, cab.length).setValues(dados);
    sh.getRange(1, 1, 1, cab.length).setFontWeight('bold').setBackground('#E9EDF5');
    sh.setFrozenRows(1);
  };

  aba('Estoque atual',
    ['Item', 'Descrição', 'Categoria', 'Unidade', 'Local', 'Saldo', 'Estoque mínimo', 'Estoque ideal', 'Fornecedor', 'Cód. fornecedor', 'Custo unitário', 'Valor em estoque', 'Controlado', 'Ativo'],
    d.itens.map(i => [i.nome, i.descricao, i.categoria, i.unidade, i.local, saldo[i.id] || 0, num_(i.estoque_minimo), num_(i.estoque_ideal),
      i.fornecedor, i.cod_fornecedor, num_(i.custo_unit), Math.round((saldo[i.id] || 0) * Number(i.custo_unit || 0) * 100) / 100,
      i.controlado ? 'Sim' : 'Não', i.ativo ? 'Sim' : 'Não']));

  aba('Lotes (formato original)',
    ['CODIGO', 'ITEM / DESCRIÇÃO', 'NOME', 'CATEGORIA', 'UNIDADE', 'QUANTIDADE', 'LOCAL PADRÃO', 'CODIGO FORNECEDOR', 'FORNECEDOR', 'CUSTO UNITARIO', 'FABRICADO', 'VALIDADE', 'LOTE'],
    d.lotes.map(l => { const i = idx[l.item_id] || {};
      return [i.codigo, i.descricao, i.nome, i.categoria, i.unidade, Number(l.quantidade), i.local, i.cod_fornecedor, i.fornecedor, num_(i.custo_unit), dt_(l.fabricacao), dt_(l.validade), l.lote]; }));

  aba('Movimentações',
    ['Data e hora', 'Tipo', 'Item', 'Lote', 'Quantidade', 'Saldo do lote', 'Motivo', 'Paciente', 'Responsável', 'Origem'],
    d.movimentacoes.map(m => [dh_(m.criado_em), TIPOS[m.tipo] || m.tipo, (idx[m.item_id] || {}).nome, (lotesIdx[m.lote_id] || {}).lote,
      Number(m.quantidade), num_(m.saldo_lote), m.motivo, m.paciente, m.usuario_nome, m.origem]));

  aba('Usuários', ['Nome', 'Perfil', 'Ativo'],
    d.usuarios.map(u => [u.nome, u.papel === 'admin' ? 'Administrador' : 'Funcionária', u.ativo ? 'Sim' : 'Não']));

  aba('Auditoria', ['Data e hora', 'Quem', 'Ação', 'Tabela', 'Registro', 'Antes', 'Depois'],
    d.auditoria.map(a => [dh_(a.criado_em), a.usuario_nome, a.acao, a.tabela, a.registro_id, JSON.stringify(a.antes || ''), JSON.stringify(a.depois || '')]));

  SpreadsheetApp.flush();
  const xlsx = UrlFetchApp.fetch('https://docs.google.com/spreadsheets/d/' + ss.getId() + '/export?format=xlsx', {
    headers: { Authorization: 'Bearer ' + ScriptApp.getOAuthToken() }
  }).getBlob().setName(nome + '.xlsx');
  pasta.createFile(xlsx);
  DriveApp.getFileById(ss.getId()).setTrashed(true); // apaga a planilha temporária

  Logger.log('Backup salvo em "' + PASTA + ' / ' + Utilities.formatDate(agora, FUSO, 'yyyy') + ' / ' + pasta.getName() + '": ' + nome + ' (.xlsx e .json) — ' +
    d.itens.length + ' itens, ' + d.lotes.length + ' lotes, ' + d.movimentacoes.length + ' movimentações.');
}

/** Rode uma vez: move os backups soltos na pasta principal para as pastas de ano e mês. */
function organizarBackupsAntigos() {
  const raiz = pasta_(); const arqs = raiz.getFiles(); let n = 0;
  while (arqs.hasNext()) {
    const f = arqs.next();
    const m = f.getName().match(/(\d{4})-(\d{2})-(\d{2})/);
    const data = m ? new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]), 12) : f.getDateCreated();
    f.moveTo(pastaDoMes_(data)); n++;
  }
  Logger.log(n ? n + ' arquivo(s) organizados nas pastas de ano e mês.' : 'Nenhum arquivo solto para organizar.');
}

/* ---------- auxiliares ---------- */
function subpasta_(mae, nome) {
  const it = mae.getFoldersByName(nome);
  return it.hasNext() ? it.next() : mae.createFolder(nome);
}
/** Backup Estoque UROtherap / AAAA / MM - Mês  (o número na frente mantém os meses em ordem) */
function pastaDoMes_(data) {
  const ano = Utilities.formatDate(data, FUSO, 'yyyy');
  const mes = Number(Utilities.formatDate(data, FUSO, 'M'));
  return subpasta_(subpasta_(pasta_(), ano), (mes < 10 ? '0' : '') + mes + ' - ' + MESES[mes - 1]);
}
function cfg_() {
  const txt = UrlFetchApp.fetch(SITE + 'config.js?t=' + Date.now()).getContentText();
  const url = (txt.match(/supabaseUrl:\s*"([^"]+)"/) || [])[1];
  const key = (txt.match(/supabaseAnonKey:\s*"([^"]+)"/) || [])[1];
  if (!url || !key) throw new Error('Não encontrei a configuração do Supabase em ' + SITE + 'config.js');
  return { url: url.replace(/\/$/, ''), key: key };
}
function rpc_(nome, corpo) {
  const c = cfg_();
  const r = UrlFetchApp.fetch(c.url + '/rest/v1/rpc/' + nome, {
    method: 'post', contentType: 'application/json', muteHttpExceptions: true,
    headers: { apikey: c.key, Authorization: 'Bearer ' + c.key },
    payload: JSON.stringify(corpo)
  });
  if (r.getResponseCode() >= 300) throw new Error('Supabase respondeu ' + r.getResponseCode() + ': ' + r.getContentText().slice(0, 300) +
    ' (se o projeto estiver pausado, entre em supabase.com e clique em Restore)');
  return JSON.parse(r.getContentText());
}
function pasta_() {
  const it = DriveApp.getFoldersByName(PASTA);
  return it.hasNext() ? it.next() : DriveApp.createFolder(PASTA);
}
function txt_(v) {
  if (v === null || v === undefined) return '';
  if (typeof v === 'string' && /^[=+\-@]/.test(v)) return "'" + v; // impede que texto vire fórmula
  if (typeof v === 'string' && v.length > 49000) return v.slice(0, 49000) + '…';
  return v;
}
function num_(v) { return v === null || v === undefined || v === '' ? '' : Number(v); }
function dt_(iso) { return iso ? String(iso).slice(8, 10) + '/' + String(iso).slice(5, 7) + '/' + String(iso).slice(0, 4) : ''; }
function dh_(ts) { return ts ? Utilities.formatDate(new Date(ts), FUSO, 'dd/MM/yyyy HH:mm') : ''; }
