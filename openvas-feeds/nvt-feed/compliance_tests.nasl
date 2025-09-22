# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.95888");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Compliance Tests");
  script_category(ACT_SETTINGS);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Compliance");

  script_add_preference(name:"Launch IT-Grundschutz (10. EL)", type:"checkbox", value:"no", id:1);
  script_add_preference(name:"Launch IT-Grundschutz (11. EL)", type:"checkbox", value:"no", id:2);
  script_add_preference(name:"Launch IT-Grundschutz (12. EL)", type:"checkbox", value:"no", id:3);
  script_add_preference(name:"Launch IT-Grundschutz (13. EL)", type:"checkbox", value:"no", id:4);
  script_add_preference(name:"Launch IT-Grundschutz (15. EL)", type:"checkbox", value:"no", id:5);
  script_add_preference(name:"Launch latest IT-Grundschutz version", type:"checkbox", value:"no", id:6);
  script_add_preference(name:"Level of Security (IT-Grundschutz)", type:"radio", value:"Basis;Standard;Kern", id:7);
  script_add_preference(name:"Verbose IT-Grundschutz results", type:"checkbox", value:"no", id:8);
  script_add_preference(name:"Launch PCI-DSS (Version 2.0)", type:"checkbox", value:"no", id:9);
  script_add_preference(name:"Launch latest PCI-DSS version", type:"checkbox", value:"no", id:10);
  script_add_preference(name:"Verbose PCI-DSS results", type:"checkbox", value:"no", id:11);
  script_add_preference(name:"Launch Cyber Essentials", type:"checkbox", value:"no", id:12);
  script_add_preference(name:"Launch EU GDPR", type:"checkbox", value:"no", id:13);
  script_add_preference(name:"Verbose Policy Controls", type:"checkbox", value:"no", id:14);
  script_add_preference(name:"Launch Compliance Test", type:"checkbox", value:"no", id:15);
  script_add_preference(name:"PCI-DSS Berichtsprache/Report Language", type:"radio", value:"Deutsch;English", id:16);
  script_add_preference(name:"Testuser Common Name", type:"entry", value:"CN", id:17);
  script_add_preference(name:"Testuser Organization Unit", type:"entry", value:"OU", id:18);
  script_add_preference(name:"Windows Domaenenfunktionsmodus", type:"radio", value:"Unbekannt;Windows 2000 gemischt und Windows 2000 pur;Windows Server 2003 Interim;Windows Server 2003;Windows Server 2008;Windows Server 2008 R2", id:19);

  script_tag(name:"summary", value:"This script controls various compliance tests like IT-Grundschutz.");

  script_tag(name:"qod_type", value:"general_note");

  exit(0);
}

launch_gshb_10 = script_get_preference("Launch IT-Grundschutz (10. EL)", id:1);
report = "Launch IT-Grundschutz (10. EL):         " + launch_gshb_10;
if(launch_gshb_10 == "yes") {
  set_kb_item(name:"Compliance/Launch/GSHB-10", value:TRUE);
  set_kb_item(name:"Compliance/Launch/GSHB", value:TRUE);
  do_report = TRUE;
}

launch_gshb_11 = script_get_preference("Launch IT-Grundschutz (11. EL)", id:2);
report += '\n' + "Launch IT-Grundschutz (11. EL):         " + launch_gshb_11;
if(launch_gshb_11 == "yes") {
  set_kb_item(name:"Compliance/Launch/GSHB-11", value:TRUE);
  set_kb_item(name:"Compliance/Launch/GSHB", value:TRUE);
  do_report = TRUE;
}

launch_gshb_12 = script_get_preference("Launch IT-Grundschutz (12. EL)", id:3);
report += '\n' + "Launch IT-Grundschutz (12. EL):         " + launch_gshb_12;
if(launch_gshb_12 == "yes") {
  set_kb_item(name:"Compliance/Launch/GSHB-12", value:TRUE);
  set_kb_item(name:"Compliance/Launch/GSHB", value:TRUE);
  do_report = TRUE;
}

launch_gshb_13 = script_get_preference("Launch IT-Grundschutz (13. EL)", id:4);
report += '\n' + "Launch IT-Grundschutz (10. EL):         " + launch_gshb_10;
if(launch_gshb_13 == "yes") {
  set_kb_item(name:"Compliance/Launch/GSHB-13", value:TRUE);
  set_kb_item(name:"Compliance/Launch/GSHB", value:TRUE);
  do_report = TRUE;
}

launch_gshb_15 = script_get_preference("Launch IT-Grundschutz (15. EL)", id:5);
report += '\n' + "Launch IT-Grundschutz (15. EL):         " + launch_gshb_15;
if(launch_gshb_15 == "yes") {
  set_kb_item(name:"Compliance/Launch/GSHB-15", value:TRUE);
  set_kb_item(name:"Compliance/Launch/GSHB", value:TRUE);
  do_report = TRUE;
}

launch_gshb = script_get_preference("Launch latest IT-Grundschutz version", id:6);
report += '\n' + "Launch latest IT-Grundschutz version:   " + launch_gshb;
if(launch_gshb == "yes") {
  set_kb_item(name:"Compliance/Launch/GSHB-ITG", value:TRUE);
  set_kb_item(name:"Compliance/Launch/GSHB", value:TRUE);
  set_kb_item(name:"Compliance/Launch", value:TRUE);
  do_report = TRUE;
}

verbose_gshb = script_get_preference("Verbose IT-Grundschutz results", id:8);
report += '\n' + "Verbose IT-Grundschutz results:         " + verbose_gshb;
if(verbose_gshb == "no") {
  set_kb_item(name:"GSHB-10/silence", value:"Wahr");
  set_kb_item(name:"GSHB-11/silence", value:"Wahr");
  set_kb_item(name:"GSHB-12/silence", value:"Wahr");
  set_kb_item(name:"GSHB-13/silence", value:"Wahr");
  set_kb_item(name:"GSHB-15/silence", value:"Wahr");
  set_kb_item(name:"GSHB/silence", value:"Wahr");
}

security_level = script_get_preference("Level of Security (IT-Grundschutz)", id:7);
report += '\n' + "Level of Security (IT-Grundschutz):     " + security_level;
set_kb_item(name:"GSHB/level", value:security_level);

launch_pci_dss = script_get_preference("Launch PCI-DSS (Version 2.0)", id:9);
report += '\n' + "Launch PCI-DSS (Version 2.0):           " + launch_pci_dss;
if(launch_pci_dss == "yes") {
  set_kb_item(name:"Compliance/Launch/PCI-DSS_2.0", value:TRUE);
  set_kb_item(name:"Compliance/Launch/GSHB", value:TRUE);
  do_report = TRUE;
}

launch_latest_pci_dss = script_get_preference("Launch latest PCI-DSS version", id:10);
report += '\n' + "Launch latest PCI-DSS version:          " + launch_latest_pci_dss;
if(launch_latest_pci_dss == "yes") {
  set_kb_item(name:"Compliance/Launch/PCI-DSS", value:TRUE);
  set_kb_item(name:"Compliance/Launch/GSHB", value:TRUE);
  do_report = TRUE;
}

lang_pci_dss = script_get_preference("PCI-DSS Berichtsprache/Report Language", id:16);
report += '\n' + "PCI-DSS Berichtsprache/Report Language: " + lang_pci_dss;
if(lang_pci_dss == "Deutsch")
  set_kb_item(name:"PCI-DSS/lang", value:"ger");
else if(lang_pci_dss == "English")
  set_kb_item(name:"PCI-DSS/lang", value:"eng");
else
  set_kb_item(name:"PCI-DSS/lang", value:"eng");

verbose_pci_dss = script_get_preference("Verbose PCI-DSS results", id:11);
report += '\n' + "Verbose PCI-DSS results:                " + verbose_pci_dss;
if(verbose_pci_dss == "no")
  set_kb_item(name:"PCI-DSS/silence", value:"Wahr");

launch_ce = script_get_preference("Launch Cyber Essentials", id:12);
report += '\n' + "Launch Cyber Essentials:                " + launch_ce;
if(launch_ce == "yes") {
  set_kb_item(name:"Compliance/Launch/CE", value:TRUE);
  set_kb_item(name:"Compliance/Launch", value:TRUE);
  do_report = TRUE;
}

launch_gdpr = script_get_preference("Launch EU GDPR", id:13);
report += '\n' + "Launch EU GDPR:                         " + launch_gdpr;
if(launch_gdpr == "yes") {
  set_kb_item(name:"Compliance/Launch/GDPR", value:TRUE);
  set_kb_item(name:"Compliance/Launch", value:TRUE);
  do_report = TRUE;
}

launch_compliance_result = script_get_preference("Launch Compliance Test", id:15);
report += '\n' + "Launch Compliance Test:                 " + launch_compliance_result;
if(launch_compliance_result == "yes") {
  set_kb_item(name:"Compliance/Launch/PolicyControlsSummary", value:TRUE);
  set_kb_item(name:"Compliance/Launch", value:TRUE);
  do_report = TRUE;
}

verbose_policy_controls = script_get_preference("Verbose Policy Controls", id:14);
report += '\n' + "Verbose Policy Controls:                " + verbose_policy_controls;
if(verbose_policy_controls == "yes") {
  set_kb_item(name:"Compliance/Launch", value:TRUE);
  set_kb_item(name:"Compliance/verbose", value:TRUE);
  do_report = TRUE;
}

CN = script_get_preference("Testuser Common Name", id:17);
OU = script_get_preference("Testuser Organization Unit", id:18);
DomFunkMod = script_get_preference("Windows Domaenenfunktionsmodus", id:19);

report += '\n' + "Testuser Common Name:                   " + CN;
report += '\n' + "Testuser Organization Unit:             " + OU;
report += '\n' + "Windows Domaenenfunktionsmodus:         " + DomFunkMod;

if(DomFunkMod == "Unbekannt")
  DomFunk = "none";
else if(DomFunkMod == "Windows 2000 gemischt und Windows 2000 pur")
  DomFunk = "0";
else if(DomFunkMod == "Windows Server 2003 Interim")
  DomFunk = "1";
else if(DomFunkMod == "Windows Server 2003")
  DomFunk = "2";
else if(DomFunkMod == "Windows Server 2008")
  DomFunk = "3";
else if(DomFunkMod == "Windows Server 2008 R2")
  DomFunk = "4";
else if(!DomFunk)
  DomFunk = "none";

set_kb_item(name:"GSHB/CN", value:CN);
set_kb_item(name:"GSHB/OU", value:OU);
set_kb_item(name:"GSHB/DomFunkMod", value:DomFunk);

if(do_report)
  log_message(data:report, port:0, proto:"Policy");

exit(0);
