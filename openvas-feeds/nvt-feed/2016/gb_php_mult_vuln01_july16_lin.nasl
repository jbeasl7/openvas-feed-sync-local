# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808199");
  script_version("2025-09-18T05:38:39+0000");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-07-14 12:14:00 +0530 (Thu, 14 Jul 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");

  script_cve_id("CVE-2015-8865", "CVE-2016-4070", "CVE-2016-4071", "CVE-2016-4072",
                "CVE-2016-4073");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.5.34, 5.6.x < 5.6.20, 7.x < 7.0.5 Multiple Vulnerabilities (Jul 2016) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Multiple integer overflows in the mbfl_strcut function in 'ext/mbstring/libmbfl/mbfl/mbfilter.c'
  script.

  - Format string vulnerability in the php_snmp_error function in 'ext/snmp/snmp.c' script.

  - An improper handling of '\0' characters by the 'phar_analyze_path' function in 'ext/phar/phar.c'
  script.

  - An integer overflow in the 'php_raw_url_encode' function in 'ext/standard/url.c' script.

  - An improper handling of continuation-level jumps in 'file_check_mem' function in 'funcs.c'
  script.");

  script_tag(name:"impact", value:"Successfully exploiting these issues allow remote attackers to
  cause a denial of service (buffer overflow and application crash) or possibly execute arbitrary
  code.");

  script_tag(name:"affected", value:"PHP prior to version 5.5.34, 5.6.x prior to 5.6.20 and 7.0.x
  prior to 7.0.5 on Linux.");

  script_tag(name:"solution", value:"Update to version 5.5.34, 5.6.20, 7.0.5 or later.");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/85800");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/85801");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/85802");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/85991");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/85993");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-7.php");

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

if (version_is_less(version: version, test_version: "5.5.34")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.34", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.6.0", test_version_up: "5.6.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.20", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0", test_version_up: "7.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
