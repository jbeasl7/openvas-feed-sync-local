# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.109040");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2018-01-29 10:14:11 +0100 (Mon, 29 Jan 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz, Kompendium");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_active");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Compliance");
  script_add_preference(name:"Berichtformat", type:"radio", value:"Text;Tabellarisch;Text und Tabellarisch", id:1);
  script_mandatory_keys("GSHB/silence", "Compliance/Launch/GSHB-ITG");
  script_dependencies("compliance_tests.nasl", "GSHB/GSHB_SYS.1.2.2.nasl", "GSHB/GSHB_SYS.1.3.nasl", "GSHB/GSHB_SYS.2.2.2.nasl", "GSHB/GSHB_SYS.2.2.3.nasl", "GSHB/GSHB_SYS.2.3.nasl");
  script_tag(name:"summary", value:"Zusammenfassung von Tests gemδί IT-Grundschutz Kompendium.

Diese Routinen prόfen sδmtliche Massnahmen des
IT-Grundschutz Kompendiums des Bundesamts fuer Sicherheit
in der Informationstechnik (BSI) auf den
Zielsystemen soweit die Maίnahmen auf automatisierte
Weise abgeprόft werden kφnnen.");

  exit(0);
}

include("GSHB/GSHB_mtitle.inc");
include("GSHB/GSHB_depend.inc");

level = get_kb_item("GSHB/level");

report = 'Prόfergebnisse gemδί IT-Grundschutz Kompendium:\n\n\n';
log = string('');

foreach m (mtitle) {
  m = split(m, sep:"|", keep:FALSE);
  m_num = m[0];
  m_title = m[1];
  m_level = m[2];

  if ((level == 'Basis' && m_level == 'Standard') ||
      (level == 'Basis' && m_level == 'Kern')){
    continue;
  }
  if (level == "Standard" && m_level == 'Kern'){
    continue;
  }

  result = get_kb_item("GSHB/" + m_num + "/result");
  desc = get_kb_item("GSHB/" + m_num + "/desc");

  if (!result){
    if (m_num >< depend){
      result = 'Diese Vorgabe muss manuell όberprόft werden.';
    }else{
      result = 'Prόfroutine fόr diese Maίnahme ist nicht verfόgbar.';
    }
  }

  if (!desc) {
    if (m_num >< depend){
      desc = 'Diese Vorgabe muss manuell όberprόft werden.';
    }else{
      desc = 'Prόfroutine fόr diese Maίnahme ist nicht verfόgbar.';
    }
    read_desc = desc;
  }else{
    read_desc = ereg_replace(pattern:'\n',replace:'\\n', string:desc);
    read_desc = ereg_replace(pattern:'\\\\n',replace:'\\n                ', string:read_desc);
  }

  report = report + ' \n' + m_num + " " + m_title + '\n' + 'Ergebnis:       ' + result +
           '\nDetails:        ' + read_desc + '\n_______________________________________________________________________________\n';

  if (result >< 'error') result = 'ERR';
  else if (result >< 'Fehler') result = 'ERR';
  else if (result >< 'erfόllt') result = 'OK';
  else if (result >< 'erfuellt') result = 'OK';
  else if (result >< 'nicht zutreffend') result = 'NS';
  else if (result >< 'nicht erfuellt') result = 'FAIL';
  else if (result >< 'nicht erfόllt') result = 'FAIL';
  else if (result >< 'unvollstaendig') result = 'NC';
  else if (result >< 'Diese Vorgabe muss manuell όberprόft werden.') result = 'NA';
  else if (result >< 'Prόfroutine fόr diese Maίnahme ist nicht verfόgbar.') result = 'NI';
  ip = get_host_ip ();
  log_desc = ereg_replace(pattern:'\n',replace:' ', string:desc);
  log_desc = ereg_replace(pattern:'\\\\n',replace:' ', string:log_desc);

  log = log + string('"' + ip + '"|"' + m_num + '"|"' + result + '"|"' + log_desc + '"') + '\n';

}

format = script_get_preference("Berichtformat");
if (format == "Text" || format == "Text und Tabellarisch") {
  security_message(port:0, proto: "IT-Grundschutz", data:report);
}
if (format == "Tabellarisch" || format == "Text und Tabellarisch") {
  log_message(port:0, proto: "IT-Grundschutz-T", data:log);
}

exit(0);
