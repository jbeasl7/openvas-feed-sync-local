# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803778");
  script_version("2025-06-03T05:40:40+0000");
  script_tag(name:"last_modification", value:"2025-06-03 05:40:40 +0000 (Tue, 03 Jun 2025)");
  script_tag(name:"creation_date", value:"2013-11-26 13:02:20 +0530 (Tue, 26 Nov 2013)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 5.3.10, 5.4.0 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl",
                      "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An error in handling 'display_errors', when display_errors is
  set to on and html_errors is set to on, may lead to cross-site scripting.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser session in the context
  of an affected site.");

  script_tag(name:"affected", value:"PHP versions 5.3.10 and 5.4.0.");

  script_tag(name:"solution", value:"Update to the latest version of PHP.");

  script_xref(name:"URL", value:"https://packetstorm.news/files/id/111695");
  script_xref(name:"URL", value:"https://web.archive.org/web/20120717162222/http://dl.packetstormsecurity.net/1204-exploits/php-xss.txt");

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

if (version_is_equal(version: version, test_version: "5.3.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "5.4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.4.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
