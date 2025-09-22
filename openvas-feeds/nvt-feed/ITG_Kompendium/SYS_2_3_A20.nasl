# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150607");
  script_version("2023-09-22T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-09-22 05:05:30 +0000 (Fri, 22 Sep 2023)");
  script_tag(name:"creation_date", value:"2021-03-15 12:19:08 +0000 (Mon, 15 Mar 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");
  script_copyright("Copyright (C) 2021 Greenbone AG");

  script_name("SYS.2.3.A20");

  script_category(ACT_GATHER_INFO);
  script_family("IT-Grundschutz");
  script_dependencies("os_detection.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch/GSHB-ITG");

  script_xref(name:"URL", value:"https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Grundschutz/Kompendium_Einzel_PDFs_2021/07_SYS_IT_Systeme/SYS_2_3_Clients_unter_Linux_und_Unix_Edition_2021.pdf?__blob=publicationFile&v=2");
  script_tag(name:"summary", value:"Es SOLLTE festgelegt werden, welche SysRq-Funktionen von den
Benutzern ausgefuehrt werden duerfen. Generell SOLLTEN keine kritischen SysRq-Funktionen von den
Benutzern ausgeloest werden koennen.");

  exit(0);
}

include("itg.inc");
include("policy_functions.inc");
include("host_details.inc");
include("os_func.inc");

if (!itg_start_requirement(level:"Kern"))
  exit(0);

title = "Abschaltung kritischer SysRq-Funktionen";

if (os_host_runs("linux") != "yes"){
  result = itg_result_wrong_target();
  desc = itg_desc_wrong_target();
  itg_set_kb_entries(result:result, desc:desc, title:title, id:"SYS.2.3.A20");
  exit(0);
}

desc = itg_no_automatic_test();
result = itg_no_automatic_test();
# Create report matching Greenbone Compliance Report requirements
report = policy_build_report(result:result, default:"None", compliant:"yes", fixtext:"None",
  type:"None", test:"None", info:desc);

itg_set_kb_entries(result:result, desc:desc, title:title, id:"SYS.2.3.A20");
itg_report(report:report);

exit(0);