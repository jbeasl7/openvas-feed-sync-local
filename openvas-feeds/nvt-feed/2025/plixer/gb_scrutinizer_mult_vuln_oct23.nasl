# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:plixer:scrutinizer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125149");
  script_version("2025-02-27T08:17:42+0000");
  script_tag(name:"last_modification", value:"2025-02-27 08:17:42 +0000 (Thu, 27 Feb 2025)");
  script_tag(name:"creation_date", value:"2025-02-25 13:21:40 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-16 18:17:04 +0000 (Mon, 16 Oct 2023)");

  script_cve_id("CVE-2023-41261", "CVE-2023-41262", "CVE-2023-41263");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Plixer / Dell SonicWALL Scrutinizer < 19.2.2, 19.3.x < 19.3.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_plixer_dell_scrutinizer_http_detect.nasl");
  script_mandatory_keys("plixer_dell/scrutinizer/http/detected");

  script_tag(name:"summary", value:"Plixer / Dell SonicWALL Scrutinizer is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-41261: An issue was discovered in /fcgi/scrut_fcgi.fcgi in Plixer Scrutinizer. The
  csvExportReport endpoint action generateCSV does not require authentication and allows an
  unauthenticated user to export a report and access the results

  - CVE-2023-41262: An issue was discovered in /fcgi/scrut_fcgi.fcgi in Plixer Scrutinizer. The
  csvExportReport endpoint action generateCSV is vulnerable to SQL injection through the sorting
  parameter, allowing an unauthenticated user to execute arbitrary SQL statements in the context of
  the application's backend database server.

  - CVE-2023-41263: An issue was discovered in Plixer Scrutinizer. It exposes debug logs to
  unauthenticated users at the /debug/ URL path. With knowledge of valid IP addresses and source
  types, an unauthenticated attacker can download debug logs containing application-related information.");

  script_tag(name:"affected", value:"Plixer / Dell SonicWALL Scrutinizer versions prior to 19.2.2 and
  19.3.x prior to 19.3.2.");

  script_tag(name:"solution", value:"Update to version 19.2.2, 19.3.2 or later.");

  script_xref(name:"URL", value:"https://github.com/atredispartners/advisories/blob/master/ATREDIS-2023-0001.md");

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

if (version_is_less(version: version, test_version: "19.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "19.2.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "19.3.0", test_version_up: "19.3.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "19.3.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
