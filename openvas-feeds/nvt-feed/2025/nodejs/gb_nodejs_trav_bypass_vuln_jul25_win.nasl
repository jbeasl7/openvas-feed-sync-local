# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nodejs:node.js";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154971");
  script_version("2025-07-18T05:44:10+0000");
  script_tag(name:"last_modification", value:"2025-07-18 05:44:10 +0000 (Fri, 18 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-07-17 04:00:26 +0000 (Thu, 17 Jul 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2025-27210");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Node.js 20.x < 20.19.4, 21.x < 22.17.1, 23.x < 24.4.1 Path Traversal Protection Bypass Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nodejs_smb_login_detect.nasl");
  script_mandatory_keys("nodejs/smb-login/detected");

  script_tag(name:"summary", value:"Node.js is prone to a path traversal bypass vulnerability in
  path.normalize().");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An incomplete fix has been identified for CVE-2025-23084,
  specifically affecting Windows device names like CON, PRN, and AUX.

  This vulnerability affects Windows users of path.join API.");

  script_tag(name:"affected", value:"Node.js version 20.x through 24.x.");

  script_tag(name:"solution", value:"Update to version 20.19.4, 22.17.1, 24.4.1 or later.");

  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/july-2025-security-releases#windows-device-names-con-prn-aux-bypass-path-traversal-protection-in-pathnormalize-cve-2025-27210---high");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/52369");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "20.0", test_version_up: "20.19.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20.19.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "21.0", test_version_up: "22.17.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "22.17.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "23.0", test_version_up: "24.4.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "24.4.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
