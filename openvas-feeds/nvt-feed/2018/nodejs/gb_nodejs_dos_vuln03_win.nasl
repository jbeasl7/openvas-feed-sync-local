# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nodejs:node.js";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813468");
  script_version("2025-06-09T05:41:14+0000");
  script_cve_id("CVE-2018-7162");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-06-09 05:41:14 +0000 (Mon, 09 Jun 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-16 13:00:00 +0000 (Tue, 16 Aug 2022)");
  script_tag(name:"creation_date", value:"2018-07-09 17:20:49 +0530 (Mon, 09 Jul 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Node.js DoS Vulnerability - 03 - Windows");

  script_tag(name:"summary", value:"Node.js is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in TLS
  implementation and triggers upon duplicate/unexpected messages during the
  handshake.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct denial of service attack.");

  script_tag(name:"affected", value:"Node.js versions 9.x prior to 9.11.2 and
  10.x prior to 10.4.1");

  script_tag(name:"solution", value:"Upgrade to Node.js version 9.11.2 or 10.4.1
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/june-2018-security-releases/");

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_nodejs_smb_login_detect.nasl");
  script_mandatory_keys("nodejs/smb-login/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( appPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe:CPE, port:appPort, exit_no_version:TRUE ) ) exit( 0 );
nodejsVer = infos["version"];
appPath = infos["location"];

if(version_in_range(version:nodejsVer, test_version:"9.0", test_version2:"9.11.1")){
  fix = "9.11.2";
}

else if(version_in_range(version:nodejsVer, test_version:"10.0", test_version2:"10.4.0")){
  fix = "10.4.1";
}

if(fix)
{
  report = report_fixed_ver(installed_version:nodejsVer, fixed_version:fix, install_path:appPath);
  security_message(port:appPort, data:report);
  exit(0);
}
exit(0);
