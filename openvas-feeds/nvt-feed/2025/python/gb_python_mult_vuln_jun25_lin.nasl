# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154642");
  script_version("2025-06-09T05:41:14+0000");
  script_tag(name:"last_modification", value:"2025-06-09 05:41:14 +0000 (Mon, 09 Jun 2025)");
  script_tag(name:"creation_date", value:"2025-06-04 02:50:25 +0000 (Wed, 04 Jun 2025)");
  script_tag(name:"cvss_base", value:"9.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:P");

  script_cve_id("CVE-2024-12718", "CVE-2025-4138", "CVE-2025-4330", "CVE-2025-4435",
                "CVE-2025-4517");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python Multiple Vulnerabilities (Jun 2025) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Python is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-12718: Allows modifying some file metadata (e.g. last modified) with filter='data' or
  file permissions (chmod) with filter='tar' of files outside the extraction directory.

  - CVE-2025-4138: Allows creating arbitrary symlinks outside the extraction directory during
  extraction with filter='data'.

  - CVE-2025-4330: Allows the extraction filter to be ignored, allowing symlink targets to point
  outside the destination directory, and the modification of some file metadata.

  - CVE-2025-4435: Filtered members not skipped with TarFile.errorlevel = 0

  - CVE-2025-4517: Allows arbitrary filesystem writes outside the extraction directory during
  extraction with filter='data'.");

  # nb: Initial versions of the CVE descriptions mentioned that only 3.12 and later are affected but
  # a later mailing list posting (linked below) outlines that earlier versions are also affected.
  script_tag(name:"affected", value:"Python versions prior to 3.9.23, 3.10.x prior to 3.10.18,
  3.11.x prior to 3.11.13, 3.12.x prior to 3.12.11 and 3.13.x prior to 3.13.4.");

  script_tag(name:"solution", value:"Update to version 3.9.23, 3.10.18, 3.11.13, 3.12.11, 3.13.4 or
  later.");

  script_xref(name:"URL", value:"https://mail.python.org/archives/list/security-announce@python.org/thread/MAXIJJCUUMCL7ATZNDVEGGHUMQMUUKLG/");
  script_xref(name:"URL", value:"https://mail.python.org/archives/list/security-announce@python.org/message/HE3RYGNB64QZAE3HZ6A64XC7PTQ5IGVE/");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/135034");
  script_xref(name:"URL", value:"https://github.com/python/cpython/pull/135037");
  script_xref(name:"URL", value:"https://docs.python.org/release/3.13.4/whatsnew/changelog.html#python-3-13-4");
  script_xref(name:"URL", value:"https://docs.python.org/release/3.12.11/whatsnew/changelog.html#python-3-12-11");
  script_xref(name:"URL", value:"https://docs.python.org/release/3.11.12/whatsnew/changelog.html#python-3-11-13");
  script_xref(name:"URL", value:"https://docs.python.org/release/3.10.18/whatsnew/changelog.html");
  script_xref(name:"URL", value:"https://docs.python.org/release/3.9.23/whatsnew/changelog.html");
  script_xref(name:"URL", value:"https://gist.github.com/sethmlarson/52398e33eff261329a0180ac1d54f42f");

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

if (version_is_less(version: version, test_version: "3.9.23")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.9.23", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.10", test_version_up: "3.10.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.10.18", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.11", test_version_up: "3.11.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.11.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.12", test_version_up: "3.12.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.12.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.13", test_version_up: "3.13.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.13.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
