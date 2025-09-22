# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809735");
  script_version("2025-05-09T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-05-09 05:40:06 +0000 (Fri, 09 May 2025)");
  script_tag(name:"creation_date", value:"2016-12-01 17:38:59 +0530 (Thu, 01 Dec 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-07 03:00:00 +0000 (Sat, 07 Jan 2017)");

  script_cve_id("CVE-2014-0207", "CVE-2014-3478", "CVE-2014-3479", "CVE-2014-3480",
                "CVE-2014-3487", "CVE-2014-3515", "CVE-2014-3981", "CVE-2014-4049",
                "CVE-2014-4721", "CVE-2014-9912");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.3.29, 5.4.x < 5.4.30, 5.5.x < 5.5.14 Multiple Vulnerabilities (Jun/Aug 2014) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2014-3981: Insecure temporary file use in the configure script

  - CVE-2014-4721: phpinfo() Type Confusion Information Leak Vulnerability

  - CVE-2014-0207: cdf_read_short_sector insufficient boundary check

  - CVE-2014-3478: mconvert incorrect handling of truncated pascal string size

  - CVE-2014-3479: cdf_check_stream_offset insufficient boundary check

  - CVE-2014-3480: cdf_count_chain insufficient boundary check

  - CVE-2014-3487: cdf_read_property_info insufficient boundary check

  - CVE-2014-4049: Fix potential segfault in dns_get_record()

  - CVE-2014-3515: unserialize() SPL ArrayObject / SPLObjectStorage Type Confusion

  - CVE-2014-9912: Buffer overflow in locale_get_display_name and uloc_getDisplayName (libicu
  4.8.1)");

  script_tag(name:"affected", value:"PHP versions 5.3.x prior to 5.3.29, 5.4.x prior to 5.4.30 and
  5.5.x prior to 5.5.14.");

  script_tag(name:"solution", value:"Update to version 5.3.29, 5.4.30, 5.5.14 or later.");

  script_xref(name:"URL", value:"http://php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67837");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68423");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68239");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68237");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68243");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68120");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68241");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68238");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=67390");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=67498");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=67326");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=67410");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=67411");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=67412");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=67413");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=67432");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=67492");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=67397");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Jun/21");
  script_xref(name:"URL", value:"https://www.sektioneins.de/en/blog/14-07-04-phpinfo-infoleak.html");
  script_xref(name:"URL", value:"http://secunia.com/advisories/59575");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "5.3.0", test_version_up: "5.3.29")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.29", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.4.0", test_version_up: "5.4.30")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.30", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.5.0", test_version_up: "5.5.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
