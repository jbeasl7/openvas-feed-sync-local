# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:bridge_cc";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832939");
  script_version("2024-04-30T05:05:26+0000");
  script_cve_id("CVE-2024-20771");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-04-30 05:05:26 +0000 (Tue, 30 Apr 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-11 09:15:07 +0000 (Thu, 11 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-04-15 16:58:36 +0530 (Mon, 15 Apr 2024)");
  script_name("Adobe Bridge Out-of-bounds Read Vulnerability (APSB24-24) - Windows");

  script_tag(name:"summary", value:"Adobe Bridge is prone to an out-of-bounds
  read vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an out-of-bounds
  read error.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to cause memory leak.");

  script_tag(name:"affected", value:"Adobe Bridge version 13.x through 13.0.6
  and 14.0.x through 14.0.2 on Windows.");

  script_tag(name:"solution", value:"Update to version 13.0.7 or 14.0.3 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/bridge/apsb24-24.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_bridge_cc_detect.nasl");
  script_mandatory_keys("Adobe/Bridge/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"14.0", test_version2:"14.0.2")) {
  fix = "14.0.3 or later";
}
else if(version_in_range(version:vers, test_version:"13.0", test_version2:"13.0.6")) {
  fix = "13.0.7 or later";
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
