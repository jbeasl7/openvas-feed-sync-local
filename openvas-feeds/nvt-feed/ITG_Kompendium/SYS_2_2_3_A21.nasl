# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.109986");
  script_version("2023-08-25T16:09:51+0000");
  script_tag(name:"last_modification", value:"2023-08-25 16:09:51 +0000 (Fri, 25 Aug 2023)");
  script_tag(name:"creation_date", value:"2019-11-18 13:20:09 +0100 (Mon, 18 Nov 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name("SYS.2.2.3.A21");
  script_xref(name:"URL", value:"https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/bausteine/SYS/SYS_2_2_3_Clients_unter_Windows_10.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB-ITG");
  script_dependencies("smb_reg_service_pack.nasl", "os_detection.nasl",
"Policy/WindowsGeneral/SystemServices/win_encrypted_file_system.nasl",
"Policy/WindowsGeneral/WindowsComponents/win_indexing_crypted_files.nasl");

  script_tag(name:"summary", value:"Ziel des Bausteins SYS.2.2.3 ist der Schutz von Informationen,
die durch und auf Windows 10-Clients verarbeiten werden.

Die Standard-Anforderung 'A21: Einsatz des Encrypting File System EFS' beschreibt den Umgang mit EFS.");

  exit(0);
}

include("itg.inc");
include("policy_functions.inc");
include("host_details.inc");
include("os_func.inc");

if (!itg_start_requirement(level:"Kern"))
  exit(0);

title = "Einsatz des Encrypting File System EFS";
desc = "Folgende Einstellungen werden getestet:
Computer Configuration\Policies\Administrative Templates\Windows Components\Search\Allow indexing of encrypted files
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EFS!EfsConfiguration";

oid_list = make_list("1.3.6.1.4.1.25623.1.0.109606",
"1.3.6.1.4.1.25623.1.0.109478");

if (!policy_host_runs_windows_10()) {
  result = itg_result_wrong_target();
  desc = itg_desc_wrong_target();
  itg_set_kb_entries(result:result, desc:desc, title:title, id:"SYS.2.2.3.A21");
  exit(0);
}

results_list = itg_get_policy_control_result(oid_list:oid_list);
result = itg_translate_result(compliant:results_list["compliant"]);
# Create report matching Greenbone Compliance Report requirements
report = policy_build_report(result:"MULTIPLE", default:"MULTIPLE", compliant:results_list["compliant"],
  fixtext:results_list["solutions"], type:"MULTIPLE", test:results_list["tests"], info:results_list["notes"]);

itg_report(report:report);
itg_set_kb_entries(result:result, desc:desc, title:title, id:"SYS.2.2.3.A21");

exit(0);