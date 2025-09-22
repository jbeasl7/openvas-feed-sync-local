# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152212");
  script_version("2024-10-11T15:39:44+0000");
  script_tag(name:"last_modification", value:"2024-10-11 15:39:44 +0000 (Fri, 11 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-05-14 03:13:27 +0000 (Tue, 14 May 2024)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");

  script_cve_id("CVE-2024-4030");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python Access Control Vulnerability (May 2024) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Python is prone to an access control vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"On Windows a directory returned by tempfile.mkdtemp() would not
  always have permissions set to restrict reading and writing to the temporary directory by other
  users, instead usually inheriting the correct permissions from the default location. Alternate
  configurations or users without a profile directory may not have the intended permissions.");

  script_tag(name:"affected", value:"Python prior to version 3.8.20, 3.9.x prior to 3.9.20, 3.10.x
  prior to 3.10.15, 3.11.x prior to 3.11.10 and 3.12.x prior to 3.12.4.");

  script_tag(name:"solution", value:"Update to version 3.8.20, 3.9.20, 3.10.15, 3.11.10, 3.12.4 or
  later.");

  script_xref(name:"URL", value:"https://mail.python.org/archives/list/security-announce@python.org/thread/PRGS5OR3N3PNPT4BMV2VAGN5GMUI5636/");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/118486");
  script_xref(name:"URL", value:"https://github.com/python/cpython/pull/118488");
  script_xref(name:"URL", value:"https://github.com/python/cpython/pull/118515");
  script_xref(name:"URL", value:"https://github.com/python/cpython/pull/118737");
  script_xref(name:"URL", value:"https://osv.dev/vulnerability/PSF-2024-3");
  script_xref(name:"URL", value:"https://docs.python.org/3/whatsnew/changelog.html#python-3-12-4-final");
  script_xref(name:"URL", value:"https://docs.python.org/3.11/whatsnew/changelog.html#python-3-11-10-final");
  script_xref(name:"URL", value:"https://docs.python.org/3.10/whatsnew/changelog.html#python-3-10-15-final");
  script_xref(name:"URL", value:"https://docs.python.org/3.9/whatsnew/changelog.html#python-3-9-20-final");
  script_xref(name:"URL", value:"https://docs.python.org/3.8/whatsnew/changelog.html#python-3-8-20-final");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE,
                                          version_regex: "^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "3.8.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.8.20", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.9", test_version_up: "3.9.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.20", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.10", test_version_up: "3.10.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.10.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.11", test_version_up: "3.11.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.11.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.12", test_version_up: "3.12.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.12.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
