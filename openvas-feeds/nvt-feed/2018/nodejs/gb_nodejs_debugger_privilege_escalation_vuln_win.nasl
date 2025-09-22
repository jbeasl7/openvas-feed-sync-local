# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nodejs:node.js";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814519");
  script_version("2025-06-09T05:41:14+0000");
  script_cve_id("CVE-2018-12120");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-06-09 05:41:14 +0000 (Mon, 09 Jun 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-06 18:00:00 +0000 (Tue, 06 Sep 2022)");
  script_tag(name:"creation_date", value:"2018-11-29 13:25:38 +0530 (Thu, 29 Nov 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Node.js 'debugger' Privilege Escalation Vulnerability - Windows");

  script_tag(name:"summary", value:"Node.js is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists in due to an error in 'Debugger'.
  Debugger port 5858 listens on any interface by default, When the debugger
  is enabled with 'node --debug' or 'node debug'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct spoofing attacks.");

  script_tag(name:"affected", value:"Node.js versions prior to 6.15.0 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Node.js version 6.15.0 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/november-2018-security-releases");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Privilege escalation");
  script_dependencies("gb_nodejs_smb_login_detect.nasl");
  script_mandatory_keys("nodejs/smb-login/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
nodejsVer = infos["version"];
appPath = infos["location"];

if(version_is_less(version:nodejsVer, test_version:"6.15.0"))
{
  report = report_fixed_ver(installed_version:nodejsVer, fixed_version:"6.15.0", install_path:appPath);
  security_message(data:report);
  exit(0);
}

exit(99);
