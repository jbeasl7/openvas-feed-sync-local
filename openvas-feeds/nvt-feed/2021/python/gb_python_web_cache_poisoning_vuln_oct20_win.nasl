# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145431");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"creation_date", value:"2021-02-23 03:20:24 +0000 (Tue, 23 Feb 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_cve_id("CVE-2021-23336");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python < 3.6.13, 3.7.x < 3.7.10, 3.8.x < 3.8.8, 3.9.x < 3.9.2 Web Cache Poisoning Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Python is prone to a web cache poisoning vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The package python is vulnerable to Web Cache Poisoning via
  urllib.parse.parse_qsl and urllib.parse.parse_qs by using a vector called parameter cloaking. When the
  attacker can separate query parameters using a semicolon, they can cause a difference in the
  interpretation of the request between the proxy (running with default configuration) and the server.");

  script_tag(name:"impact", value:"Successful exploitation can result in malicious requests being cached as
  completely safe ones, as the proxy would usually not see the semicolon as a separator, and therefore would
  not include it in a cache key of an unkeyed parameter.");

  script_tag(name:"affected", value:"Python prior to version 3.6.13, versions 3.7.x prior to 3.7.10, 3.8.x prior
  to 3.8.8 and 3.9.x prior to 3.9.2.");

  script_tag(name:"solution", value:"Update to version 3.6.13, 3.7.10, 3.8.8, 3.9.2 or later.");

  script_xref(name:"URL", value:"https://snyk.io/vuln/SNYK-UPSTREAM-PYTHONCPYTHON-1074933");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "3.6.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.6.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.7.0", test_version2: "3.7.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.7.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.8.0", test_version2: "3.8.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.8.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.9.0", test_version2: "3.9.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
