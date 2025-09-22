# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nodejs:node.js";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814522");
  script_version("2025-04-30T05:39:51+0000");
  script_tag(name:"last_modification", value:"2025-04-30 05:39:51 +0000 (Wed, 30 Apr 2025)");
  script_tag(name:"creation_date", value:"2018-11-29 13:55:51 +0530 (Thu, 29 Nov 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-29 20:24:00 +0000 (Mon, 29 Aug 2022)");

  script_cve_id("CVE-2018-12116");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Node.js 'HTTP Splitting' Privilege Escalation Vulnerability - Mac OS X");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_nodejs_detect_macosx.nasl");
  script_mandatory_keys("Nodejs/MacOSX/Ver");

  script_tag(name:"summary", value:"Node.js is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists in due to an error in HTTP request splitting.
  If Node.js can be convinced to use unsanitized user-provided Unicode data for the `path` option of
  an HTTP request, then data can be provided which will trigger a second, unexpected, and
  user-defined HTTP request to made to the same server.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct
  spoofing attacks.");

  script_tag(name:"affected", value:"Node.js version 6.x prior to 6.15.0 and 8.x prior to 8.14.0
  on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 6.15.0, 8.14.0 or later.");

  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/november-2018-security-releases");

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

if (version_in_range_exclusive(version: version, test_version_lo: "6.0", test_version_up: "6.15.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.15.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.0", test_version_up: "8.14.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.14.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
