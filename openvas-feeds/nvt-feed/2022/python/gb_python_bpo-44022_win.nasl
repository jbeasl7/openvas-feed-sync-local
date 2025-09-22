# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147772");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"creation_date", value:"2022-03-08 06:11:17 +0000 (Tue, 08 Mar 2022)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-15 17:01:00 +0000 (Tue, 15 Mar 2022)");

  script_cve_id("CVE-2021-3737");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python DoS Vulnerability (bpo-44022) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Python is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"If a client request a HTTP/HTTPS/FTP service which is
  controlled by attacker, attacker can make this client hang forever, even if the client has set a
  timeout argument.");

  script_tag(name:"affected", value:"Python prior to version 3.6.14, version 3.7.x through 3.7.10,
  3.8.x through 3.8.10 and 3.9.x through 3.9.5.");

  script_tag(name:"solution", value:"Update to version 3.6.14, 3.7.11, 3.8.11, 3.9.6 or later.");

  script_xref(name:"URL", value:"https://python-security.readthedocs.io/vuln/urllib-100-continue-loop.html");
  script_xref(name:"Advisory-ID", value:"bpo-44022");

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

if (version_is_less(version: version, test_version: "3.6.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.6.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.7.0", test_version_up: "3.7.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.7.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.8.0", test_version_up: "3.8.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.8.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.9.0", test_version_up: "3.9.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
