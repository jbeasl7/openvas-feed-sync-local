# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.109967");
  script_version("2023-08-22T05:06:00+0000");
  script_tag(name:"last_modification", value:"2023-08-22 05:06:00 +0000 (Tue, 22 Aug 2023)");
  script_tag(name:"creation_date", value:"2019-11-18 13:20:09 +0100 (Mon, 18 Nov 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_name("SYS.2.2.3.A1");
  script_xref(name:"URL", value:"https://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKompendium/bausteine/SYS/SYS_2_2_3_Clients_unter_Windows_10.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB-ITG");
  script_dependencies("smb_reg_service_pack.nasl", "os_detection.nasl",
"Policy/Windows10/SystemServices/win_push_notifications.nasl",
"Policy/WindowsGeneral/ControlPanel/win_cp_input_personalization.nasl",
"Policy/Windows10/WindowsComponents/win_microsoft_consumer_experiences.nasl",
"Policy/WindowsGeneral/WindowsComponents/prevent_onedrive_file_storage.nasl",
"Policy/Windows10/UserTemplates/win_spotlight_lockscreen.nasl",
"Policy/Windows10/UserTemplates/win_spotlight_third_party.nasl",
"Policy/Windows10/UserTemplates/win_dignostic_data_experience.nasl",
"Policy/Windows10/UserTemplates/win_spotlight_features.nasl");

  script_tag(name:"summary", value:"Ziel des Bausteins SYS.2.2.3 ist der Schutz von Informationen,
die durch und auf Windows 10-Clients verarbeiten werden.

Die Basis-Anforderung 'A1: Planung des Einsatzes von Cloud-Diensten' beschreibt,
dass der Einsatz von Cloud-Services einer strategischen Festlegung folgen muss.");

  exit(0);
}

include("itg.inc");
include("policy_functions.inc");
include("host_details.inc");
include("os_func.inc");

if (!itg_start_requirement(level:"Basis"))
  exit(0);

title = "Planung des Einsatzes von Cloud-Diensten";
desc = "Folgende Einstellungen werden getestet:
Computer Configuration\Policies\Windows Settings\Security Settings\System Services\Windows Push Notifications System Service,
Computer Configuration\Policies\Administrative Templates\Control Panel\Regional and Language Options\Allow Input Personalization,
Computer Configuration\Policies\Administrative Templates\Windows Components\Cloud Content\Turn off Microsoft consumer experiences,
Computer Configuration\Policies\Administrative Templates\Windows Components\OneDrive\Prevent the usage of OneDrive for file storage,
User Configuration\Policies\Administrative Templates\Windows Components\Cloud Content\Configure Windows spotlight on Lock Screen,
User Configuration\Policies\Administrative Templates\Windows Components\Cloud Content\Do not suggest third-party content in Windows spotlight,
User Configuration\Policies\Administrative Templates\Windows Components\Cloud Content\Do not use diagnostic data for tailored experiences,
User Configuration\Policies\Administrative Templates\Windows Components\Cloud Content\Turn off all Windows spotlight features";

oid_list = make_list("1.3.6.1.4.1.25623.1.0.109286",
"1.3.6.1.4.1.25623.1.0.109297",
"1.3.6.1.4.1.25623.1.0.109430",
"1.3.6.1.4.1.25623.1.0.109095",
"1.3.6.1.4.1.25623.1.0.109520",
"1.3.6.1.4.1.25623.1.0.109521",
"1.3.6.1.4.1.25623.1.0.109522",
"1.3.6.1.4.1.25623.1.0.109523");

if (!policy_host_runs_windows_10()) {
  result = itg_result_wrong_target();
  desc = itg_desc_wrong_target();
  itg_set_kb_entries(result:result, desc:desc, title:title, id:"SYS.2.2.3.A1");
  exit(0);
}

results_list = itg_get_policy_control_result(oid_list:oid_list);
result = itg_translate_result(compliant:results_list["compliant"]);
# Create report matching Greenbone Compliance Report requirements
report = policy_build_report(result:"MULTIPLE", default:"MULTIPLE", compliant:results_list["compliant"],
  fixtext:results_list["solutions"], type:"MULTIPLE", test:results_list["tests"], info:results_list["notes"]);

itg_report(report:report);
itg_set_kb_entries(result:result, desc:desc, title:title, id:"SYS.2.2.3.A1");

exit(0);