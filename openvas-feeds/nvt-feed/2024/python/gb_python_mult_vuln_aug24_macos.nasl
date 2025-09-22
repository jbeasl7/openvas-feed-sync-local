# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170807");
  script_version("2024-12-13T15:40:54+0000");
  script_tag(name:"last_modification", value:"2024-12-13 15:40:54 +0000 (Fri, 13 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-08-28 09:54:13 +0000 (Wed, 28 Aug 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-04 14:28:41 +0000 (Wed, 04 Sep 2024)");

  script_cve_id("CVE-2024-6232", "CVE-2024-7592", "CVE-2024-8088", "CVE-2024-45490",
                "CVE-2024-45491", "CVE-2024-45492");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python Multiple Vulnerabilities (Aug 2024) - Mac OS X");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_python_consolidation.nasl");
  script_mandatory_keys("python/mac-os-x/detected");

  script_tag(name:"summary", value:"Python is prone to an infinite loop vulnerability leading to a
  denial of service (DoS).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-6232: Regular expressions that allowed excessive backtracking during tarfile.TarFile
  header parsing are vulnerable to ReDoS via specifically-crafted tar archives.

  - CVE-2024-7592: When parsing cookies that contained backslashes for quoted characters in the
  cookie value, the parser would use an algorithm with quadratic complexity, resulting in excess
  CPU resources being used while parsing the value.

  - CVE-2024-8088: When iterating over names of entries in a zip archive (for example, methods of
  'zipfile.Path' like 'namelist()', 'iterdir()', etc) the process can be put into an infinite loop
  with a maliciously crafted zip archive. This defect applies when reading only metadata or
  extracting the contents of the zip archive.This vulnerability only affects zipfile.Path, while the
  more common API zipfile.ZipFile class is unaffected.

  - CVE-2024-45490, CVE-2024-45491, CVE-2024-45492: vulnerabilities in libexpat prior to version
  2.6.3");

  script_tag(name:"affected", value:"Python prior to version 3.8.20, 3.9.x prior to 3.9.20, 3.10.x
  prior to 3.10.15, 3.11.x prior to 3.11.10 and 3.12.x prior to 3.12.6.");

  script_tag(name:"solution", value:"Update to version 3.8.20, 3.9.20, 3.10.15, 3.11.10, 3.12.6 or
  later.");

  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/123678");
  script_xref(name:"URL", value:"https://mail.python.org/archives/list/security-announce@python.org/thread/JRYFTPRHZRTLMZLWQEUHZSJXNHM4ACTY/");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/121285");
  script_xref(name:"URL", value:"https://github.com/python/cpython/pull/121286");
  script_xref(name:"URL", value:"https://mail.python.org/archives/list/security-announce@python.org/thread/HXJAAAALNUNGCQUS2W7WR6GFIZIHFOOK/");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/123067");
  script_xref(name:"URL", value:"https://github.com/python/cpython/pull/123075");
  script_xref(name:"URL", value:"https://mail.python.org/archives/list/security-announce@python.org/thread/GNFCKVI4TCATKQLALJ5SN4L4CSPSMILU/");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/122905");
  script_xref(name:"URL", value:"https://github.com/python/cpython/pull/122906");
  script_xref(name:"URL", value:"https://docs.python.org/3/whatsnew/changelog.html#python-3-12-6-final");
  script_xref(name:"URL", value:"https://docs.python.org/3.11/whatsnew/changelog.html#python-3-11-10-final");
  script_xref(name:"URL", value:"https://docs.python.org/3.10/whatsnew/changelog.html#python-3-10-15-final");
  script_xref(name:"URL", value:"https://docs.python.org/3.9/whatsnew/changelog.html#python-3-9-20-final");
  script_xref(name:"URL", value:"https://docs.python.org/3.8/whatsnew/changelog.html#python-3-8-20-final");
  script_xref(name:"URL", value:"https://osv.dev/vulnerability/PSF-2024-9");
  script_xref(name:"URL", value:"https://osv.dev/vulnerability/PSF-2024-10");
  script_xref(name:"URL", value:"https://osv.dev/vulnerability/PSF-2024-11");
  script_xref(name:"URL", value:"https://osv.dev/vulnerability/CVE-2024-45490");
  script_xref(name:"URL", value:"https://osv.dev/vulnerability/CVE-2024-45491");
  script_xref(name:"URL", value:"https://osv.dev/vulnerability/CVE-2024-45492");

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

if (version_in_range_exclusive(version: version, test_version_lo: "3.12", test_version_up: "3.12.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.12.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
