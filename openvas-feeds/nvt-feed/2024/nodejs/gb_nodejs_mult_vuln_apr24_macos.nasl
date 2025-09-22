# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nodejs:node.js";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152025");
  script_version("2024-06-28T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-04-04 02:48:42 +0000 (Thu, 04 Apr 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2024-27982", "CVE-2024-27983");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Node.js Multiple Vulnerabilities (Apr 2024) - Mac OS X");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_nodejs_detect_macosx.nasl");
  script_mandatory_keys("Nodejs/MacOSX/Ver");

  script_tag(name:"summary", value:"Node.js is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-27982: HTTP request smuggling via Content Length obfuscation

  - CVE-2024-27983: Assertion failed in node::http2::Http2Session::~Http2Session() leads to HTTP/2
  server crash");

  script_tag(name:"affected", value:"Node.js versions 21.x and earlier.

  Vendor note: It's important to note that End-of-Life versions are always affected when a security
  release occurs.");

  script_tag(name:"solution", value:"Update to version 18.20.1, 20.12.1, 21.7.2 or later.");

  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/april-2024-security-releases");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/blob/main/doc/changelogs/CHANGELOG_V18.md#18.20.1");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/blob/main/doc/changelogs/CHANGELOG_V20.md#20.12.1");
  script_xref(name:"URL", value:"https://github.com/nodejs/node/blob/main/doc/changelogs/CHANGELOG_V21.md#21.7.2");
  script_xref(name:"URL", value:"https://kb.cert.org/vuls/id/421644");
  script_xref(name:"URL", value:"https://nowotarski.info/http2-continuation-flood/");
  script_xref(name:"URL", value:"https://nowotarski.info/http2-continuation-flood-technical-details/");

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

# nb: From the Jul 2024 advisory:
#
# > It's important to note that End-of-Life versions are always affected when a security release occurs
if (version_is_less(version: version, test_version: "18.20.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "18.20.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "19.0", test_version_up: "20.12.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20.12.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "21.0", test_version_up: "21.7.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "21.7.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
