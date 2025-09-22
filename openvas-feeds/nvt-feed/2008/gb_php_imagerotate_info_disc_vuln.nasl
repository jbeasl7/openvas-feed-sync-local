# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900186");
  script_version("2025-05-06T05:40:10+0000");
  script_tag(name:"last_modification", value:"2025-05-06 05:40:10 +0000 (Tue, 06 May 2025)");
  script_tag(name:"creation_date", value:"2008-12-31 15:14:17 +0100 (Wed, 31 Dec 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2008-5498");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 5.x < 5.2.9 Memory Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to a memory information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper validation of bgd_color or
  clrBack argument in imageRotate function.");

  script_tag(name:"impact", value:"Successful exploitation could let the attacker read the
  contents of arbitrary memory locations through a crafted value for an indexed image.");

  script_tag(name:"affected", value:"PHP versions 5.x through 5.2.8.");

  script_tag(name:"solution", value:"Update to version 5.2.9 or later.");

  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2008/Dec/1021494.html");
  script_xref(name:"URL", value:"https://web.archive.org/web/20101223093311/http://www.securityfocus.com/bid/33002");
  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/33002.php");
  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/33002-2.php");

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

if (version_in_range(version: version, test_version: "5.0", test_version2: "5.2.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
