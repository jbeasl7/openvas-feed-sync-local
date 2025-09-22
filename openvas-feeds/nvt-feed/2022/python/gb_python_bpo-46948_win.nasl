# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147785");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"creation_date", value:"2022-03-14 02:47:00 +0000 (Mon, 14 Mar 2022)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-18 19:24:00 +0000 (Fri, 18 Mar 2022)");

  script_cve_id("CVE-2022-26488");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python Privilege Escalation Vulnerability (bpo-46948) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Python is prone to a privilege escalation vulnerability in the
  Windows installer.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability exists when installed for all users with the
  'Add Python to PATH' option selected. A local user without administrative permissions can trigger
  a repair operation of this PATH option to add incorrect additional paths to the system PATH
  variable, and then use search path hijacking to achieve escalation of privilege. Per-user
  installs (the default) are also affected, but cannot be used for escalation of privilege.");

  script_tag(name:"affected", value:"Python prior to version 3.7.13, version 3.8.x through 3.8.12,
  3.9.x through 3.9.10, 3.10.x through 3.10.2 and 3.11.x through 3.11.0a6.");

  script_tag(name:"solution", value:"Update to version 3.7.13, 3.8.13, 3.9.11, 3.10.3, 3.11.0b1 or
  later.");

  script_xref(name:"URL", value:"https://mail.python.org/archives/list/security-announce@python.org/thread/657Z4XULWZNIY5FRP3OWXHYKUSIH6DMN/");
  script_xref(name:"Advisory-ID", value:"bpo-46948");

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

if (version_is_less(version: version, test_version: "3.7.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.7.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.8.0", test_version_up: "3.8.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.8.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.9.0", test_version_up: "3.9.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.10.0", test_version_up: "3.10.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.10.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.11.0a", test_version_up: "3.11.0b1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.11.0b1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
