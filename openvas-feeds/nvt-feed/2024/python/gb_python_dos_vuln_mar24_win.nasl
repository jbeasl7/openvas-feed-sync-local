# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170815");
  script_version("2024-10-11T15:39:44+0000");
  script_tag(name:"last_modification", value:"2024-10-11 15:39:44 +0000 (Fri, 11 Oct 2024)");
  # nb: This was initially a single VT but got split later into multiple due to different affected /
  # fixed versions. Thus the original creation_date of the first VT has been kept.
  script_tag(name:"creation_date", value:"2024-03-20 08:50:29 +0000 (Wed, 20 Mar 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-09 02:03:16 +0000 (Fri, 09 Feb 2024)");

  script_cve_id("CVE-2023-52425");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python DoS Vulnerability (Mar 2024) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Python is prone to a denial of service (DoS) vulnerability in
  libexpat.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"libexpat allows a denial of service (resource consumption)
  because many full reparsings are required in the case of a large token for which multiple buffer
  fills are needed.

  Also, on Windows urllib.request no longer resolves the hostname before checking it against the
  system's proxy bypass list.");

  script_tag(name:"affected", value:"Python prior to version 3.8.19, 3.9.x prior to 3.9.19, 3.10.x
  prior to 3.10.14, 3.11.x prior to 3.11.9 and 3.12.x prior to 3.12.3.");

  script_tag(name:"solution", value:"Update to version 3.8.19, 3.9.19, 3.10.14, 3.11.9, 3.12.3
  or later.");

  script_xref(name:"URL", value:"https://discuss.python.org/t/python-3-10-14-3-9-19-and-3-8-19-is-now-available/48993");
  script_xref(name:"URL", value:"https://pythoninsider.blogspot.com/2024/03/python-31014-3919-and-3819-is-now.html");
  script_xref(name:"URL", value:"https://osv.dev/vulnerability/CVE-2023-52425");
  script_xref(name:"URL", value:"https://docs.python.org/3.11/whatsnew/changelog.html#python-3-11-9-final");
  script_xref(name:"URL", value:"https://docs.python.org/3.12/whatsnew/changelog.html#python-3-12-3-final");

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
