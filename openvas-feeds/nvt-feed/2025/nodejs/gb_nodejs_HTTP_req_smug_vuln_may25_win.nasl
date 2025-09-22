# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nodejs:node.js";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128136");
  script_version("2025-06-09T05:41:14+0000");
  script_tag(name:"last_modification", value:"2025-06-09 05:41:14 +0000 (Mon, 09 Jun 2025)");
  script_tag(name:"creation_date", value:"2025-05-23 03:55:57 +0000 (Fri, 23 May 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2025-23167");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Node.js < 20.19.2 HTTP Request Smuggling Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_nodejs_smb_login_detect.nasl");
  script_mandatory_keys("nodejs/smb-login/detected");

  script_tag(name:"summary", value:"Node.js is prone to an HTTP request smuggling vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A flaw in Node.js 20's HTTP parser allows improper termination
  of HTTP/1 headers using `\r\n\rX` instead of the required `\r\n\r\n`. This inconsistency enables
  request smuggling, allowing attackers to bypass proxy-based access controls and submit
  unauthorized requests.");

  script_tag(name:"affected", value:"Node.js prior to version 20.19.2.");

  script_tag(name:"solution", value:"Update to version 20.19.2 or later.");

  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/may-2025-security-releases");
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

if (version_is_less(version: version, test_version: "20.19.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20.19.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
