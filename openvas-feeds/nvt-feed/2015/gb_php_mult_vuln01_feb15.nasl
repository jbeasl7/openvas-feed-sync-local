# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805446");
  script_version("2025-05-06T05:40:10+0000");
  script_tag(name:"last_modification", value:"2025-05-06 05:40:10 +0000 (Tue, 06 May 2025)");
  script_tag(name:"creation_date", value:"2015-02-06 11:43:37 +0530 (Fri, 06 Feb 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2014-9652", "CVE-2014-9653", "CVE-2015-0231", "CVE-2015-0232");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 5.4.x < 5.4.37, 5.5.x < 5.5.21, 5.6.x < 5.6.5 Multiple Vulnerabilities (Feb 2015)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2014-9652: Improper handle of a certain string-length field during a copy of a truncated
  version of a Pascal string in the mconvert function from softmagic.c file

  - CVE-2014-9653: Uninitialized memory access in the readelf.c file

  - CVE-2015-0231: Use after free vulnerability in the 'process_nested_data' function in
  ext/standard/var_unserializer.re

  - CVE-2015-0232: Uninitialized pointer free in the 'exif_process_unicode' function in
  ext/exif/exif.c script when parsing JPEG EXIF entries");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a
  denial of service or possibly execute arbitrary code via different crafted dimensions.");

  script_tag(name:"affected", value:"PHP versions 5.4.x before 5.4.37, 5.5.x before 5.5.21, and
  5.6.x before 5.6.5.");

  script_tag(name:"solution", value:"Update to PHP version 5.4.37, 5.5.21, 5.6.5 or later.");

  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=68799");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72505");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72516");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72541");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72539");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=68710");

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

if (version_in_range_exclusive(version: version, test_version_lo: "5.4.0", test_version_up: "5.4.37")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.37", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.5.0", test_version_up: "5.5.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.21", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.6.0", test_version_up: "5.6.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
