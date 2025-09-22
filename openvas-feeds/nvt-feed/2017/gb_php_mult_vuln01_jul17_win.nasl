# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811481");
  script_version("2025-05-09T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-05-09 05:40:06 +0000 (Fri, 09 May 2025)");
  script_tag(name:"creation_date", value:"2017-07-11 19:28:21 +0530 (Tue, 11 Jul 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-20 16:38:00 +0000 (Wed, 20 Jul 2022)");

  script_cve_id("CVE-2017-11144", "CVE-2017-11145", "CVE-2017-11628", "CVE-2017-12933",
                "CVE-2017-7890", "CVE-2017-9224", "CVE-2017-9225", "CVE-2017-9226",
                "CVE-2017-9227", "CVE-2017-9228", "CVE-2017-9229");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.6.31, 7.0.x < 7.0.21, 7.1.x < 7.1.7 Multiple Vulnerabilities (Jul 2017) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - An ext/date/lib/parse_date.c out-of-bounds read affecting the php_parse_date function.

  - The openssl extension PEM sealing code did not check the return value of the OpenSSL sealing
  function.

  - lack of bounds checks in the date extension's timelib_meridian parsing code.

  - A stack-based buffer overflow in the zend_ini_do_op() function in the 'Zend/zend_ini_parser.c'
  script.

  - The GIF decoding function gdImageCreateFromGifCtx in gd_gif_in.c in the GD Graphics Library (aka
  libgd) does not zero colorMap arrays before use.

  - Heap buffer overread (READ: 1) finish_nested_data from unserialize

  - oniguruma upstream fix");

  script_tag(name:"impact", value:"Successfully exploiting these issues allow remote attackers to
  leak information from the interpreter, crash PHP interpreter and also disclose sensitive
  information.");

  script_tag(name:"affected", value:"PHP prior to version 5.6.31, 7.0.x prior to 7.0.21 and 7.1.x
  prior to 7.1.7.");

  script_tag(name:"solution", value:"Update to version 5.6.31, 7.0.21, 7.1.7 or later.");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99492");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99550");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99605");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99612");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99489");
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

if (version_is_less(version: version, test_version: "5.6.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.31", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0", test_version_up: "7.0.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.21", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.1.0", test_version_up: "7.1.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
