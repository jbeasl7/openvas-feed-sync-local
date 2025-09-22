# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151951");
  script_version("2024-10-11T15:39:44+0000");
  script_tag(name:"last_modification", value:"2024-10-11 15:39:44 +0000 (Fri, 11 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-03-20 08:18:47 +0000 (Wed, 20 Mar 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2024-0450");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python Multiple Vulnerabilities (Mar 2024) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Python is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-0450: Quoted zip-bomb protection for zipfile

  - No CVE: crash in socket.if_indextoname() with a specific value (UINT_MAX).

  - No CVE: .pth files with names starting with a dot or containing the hidden file attribute are
  not skipped");

  script_tag(name:"affected", value:"Python prior to version 3.8.19, 3.9.x prior to 3.9.19, 3.10.x
  prior to 3.10.14, 3.11.x prior to 3.11.8 and 3.12.x prior to 3.12.2.");

  script_tag(name:"solution", value:"Update to version 3.8.19, 3.9.19, 3.10.14, 3.11.8, 3.12.2
  or later.");

  script_xref(name:"URL", value:"https://discuss.python.org/t/python-3-10-14-3-9-19-and-3-8-19-is-now-available/48993");
  script_xref(name:"URL", value:"https://pythoninsider.blogspot.com/2024/03/python-31014-3919-and-3819-is-now.html");
  script_xref(name:"URL", value:"https://mail.python.org/archives/list/security-announce@python.org/thread/XELNUX2L3IOHBTFU7RQHCY6OUVEWZ2FG/");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/109858");
  script_xref(name:"URL", value:"https://osv.dev/vulnerability/PSF-2024-2");
  script_xref(name:"URL", value:"https://docs.python.org/3.12/whatsnew/changelog.html#python-3-12-2-final");
  script_xref(name:"URL", value:"https://docs.python.org/3.11/whatsnew/changelog.html#python-3-11-8-final");

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

if (version_is_less(version: version, test_version: "3.8.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.8.19", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.9", test_version_up: "3.9.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.19", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.10", test_version_up: "3.10.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.10.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.11", test_version_up: "3.11.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.11.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.12", test_version_up: "3.12.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.12.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
