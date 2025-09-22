# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808601");
  script_version("2025-09-18T05:38:39+0000");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-07-14 12:14:00 +0530 (Thu, 14 Jul 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-20 16:56:00 +0000 (Wed, 20 Jul 2022)");

  script_cve_id("CVE-2016-4344", "CVE-2016-4345", "CVE-2016-4346");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 7.x < 7.0.4 Multiple Vulnerabilities (Jul 2016) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - An integer overflow in the 'str_pad' function in 'ext/standard/string.c' script.

  - An integer overflow in the 'xml_utf8_encode' function in 'ext/xml/xml.c' script.

  - An integer overflow in the 'php_filter_encode_url' function in 'ext/filter/sanitizing_filters.c'
  script.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow remote attackers to
  cause a denial of service or possibly have unspecified other impact.");

  script_tag(name:"affected", value:"PHP versions 7.0.x prior to 7.0.4 on Linux.");

  script_tag(name:"solution", value:"Update to version 7.0.4 or later.");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-7.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/84351");

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

if (version_in_range(version: version, test_version: "7.0", test_version2: "7.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
