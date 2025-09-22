# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nodejs:node.js";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153857");
  script_version("2025-03-17T05:38:35+0000");
  script_tag(name:"last_modification", value:"2025-03-17 05:38:35 +0000 (Mon, 17 Mar 2025)");
  script_tag(name:"creation_date", value:"2025-01-23 04:05:15 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2025-23085", "CVE-2025-23087", "CVE-2025-23088", "CVE-2025-23089");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Node.js < 18.20.6, 20.x < 20.18.2, 21.x < 22.13.1, 23.x < 23.6.1 Multiple Vulnerabilities - Mac OS X");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_nodejs_detect_macosx.nasl");
  script_mandatory_keys("Nodejs/MacOSX/Ver");

  script_tag(name:"summary", value:"Node.js is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2025-23084: Path traversal by drive name in Windows environment

  - CVE-2025-23085: GOAWAY HTTP/2 frames cause memory leak outside heap

  - CVE-2025-23087, CVE-2025-23088, CVE-2025-23089: Various fixes in EOL versions

  Note: CVE-2025-23087, CVE-2025-23088 and CVE-2025-23089 have been marked as 'Rejected' in the CVE
  list but still used / referenced by the vendor. They have been kept in this VT on purpose. Please
  see the vendor statement on these linked in the references.");

  script_tag(name:"affected", value:"Node.js version 23.x and prior.");

  script_tag(name:"solution", value:"Update to version 18.20.6, 20.18.2, 22.13.1, 23.6.1 or
  later.");

  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/january-2025-security-releases");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/upcoming-cve-for-eol-versions");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/updates-cve-for-end-of-life");

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

if (version_is_less(version: version, test_version: "18.20.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "18.20.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "20.0", test_version_up: "20.18.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20.18.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "21.0", test_version_up: "22.13.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "22.13.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "23.0", test_version_up: "22.13.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "22.13.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
