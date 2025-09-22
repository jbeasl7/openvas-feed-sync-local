# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152433");
  script_version("2024-10-11T15:39:44+0000");
  script_tag(name:"last_modification", value:"2024-10-11 15:39:44 +0000 (Fri, 11 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-06-18 02:47:02 +0000 (Tue, 18 Jun 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2024-0397");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python SSL Vulnerability (Jun 2024) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Python is prone to a vulnerability in the ssl module.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A defect was discovered in the Python 'ssl' module where there
  is a memory race condition with the ssl.SSLContext methods 'cert_store_stats()' and
  'get_ca_certs()'. The race condition can be triggered if the methods are called at the same time
  as certificates are loaded into the SSLContext, such as during the TLS handshake with a
  certificate directory configured.");

  script_tag(name:"affected", value:"Python prior to version 3.8.20, 3.9.x prior to 3.9.20, 3.10.x
  prior to 3.10.14, 3.11.x prior to 3.11.9 and 3.12.x prior to 3.12.3.");

  script_tag(name:"solution", value:"Update to version 3.8.20, 3.9.20, 3.10.14, 3.11.9, 3.12.3
  or later.");

  script_xref(name:"URL", value:"https://mail.python.org/archives/list/security-announce@python.org/thread/BMAK5BCGKYWNJOACVUSLUF6SFGBIM4VP/");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/114572");
  script_xref(name:"URL", value:"https://github.com/python/cpython/pull/114573");
  script_xref(name:"URL", value:"https://osv.dev/vulnerability/PSF-2024-4");
  script_xref(name:"URL", value:"https://docs.python.org/3/whatsnew/changelog.html#python-3-12-3-final");
  script_xref(name:"URL", value:"https://docs.python.org/3.11/whatsnew/changelog.html#python-3-11-9-final");
  script_xref(name:"URL", value:"https://docs.python.org/3.10/whatsnew/changelog.html#python-3-10-14-final");
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

if (version_in_range_exclusive(version: version, test_version_lo: "3.10", test_version_up: "3.10.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.10.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.11", test_version_up: "3.11.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.11.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.12", test_version_up: "3.12.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.12.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
