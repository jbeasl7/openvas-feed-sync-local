# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:hp:support_solution_framework";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812945");
  script_version("2025-07-30T05:45:23+0000");
  script_cve_id("CVE-2017-2744");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-07-30 05:45:23 +0000 (Wed, 30 Jul 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-09 18:13:00 +0000 (Fri, 09 Feb 2018)");
  script_tag(name:"creation_date", value:"2018-02-23 11:48:49 +0530 (Fri, 23 Feb 2018)");
  script_name("HP Support Assistant Privilege Escalation Vulnerability - Windows");

  script_tag(name:"summary", value:"HP Support Assistant is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to some unspecified
  error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to gain escalated privileges and extract binaries into protected file system
  locations.");

  script_tag(name:"affected", value:"HP Support Assistant 8 with framework version
  prior to 12.7.26.1 on Windows.");

  script_tag(name:"solution", value:"Upgrade to latest HP Support Assistant with
  framework version 12.7.26.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/c05648974");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_hp_support_assistant_detect.nasl");
  script_mandatory_keys("hp/support_assistant/detected", "hp/support_solutions_framework/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"12.7.26.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"Apply updates from vendor", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
