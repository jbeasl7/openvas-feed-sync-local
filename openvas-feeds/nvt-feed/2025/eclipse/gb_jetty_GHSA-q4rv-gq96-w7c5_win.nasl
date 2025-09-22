# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127884");
  script_version("2025-05-21T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-05-21 05:40:19 +0000 (Wed, 21 May 2025)");
  script_tag(name:"creation_date", value:"2025-05-15 08:51:24 +0000 (Thu, 15 May 2025)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");

  script_cve_id("CVE-2024-13009");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Eclipse Jetty Information Disclosure Vulnerability (GHSA-q4rv-gq96-w7c5) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_jetty_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jetty/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Eclipse Jetty is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A buffer can be incorrectly released when confronted with a
  gzip error when inflating a request body. This can result in corrupted and/or inadvertent sharing
  of data between requests.");

  script_tag(name:"affected", value:"Eclipse Jetty version 9.4.x through 9.4.57.");

  script_tag(name:"solution", value:"Update to version 9.4.57 or later.");

  script_xref(name:"URL", value:"https://github.com/jetty/jetty.project/security/advisories/GHSA-q4rv-gq96-w7c5");
  script_xref(name:"URL", value:"https://gitlab.eclipse.org/security/cve-assignement/-/issues/48");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "9.4.0", test_version_up: "9.4.57")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.57", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
