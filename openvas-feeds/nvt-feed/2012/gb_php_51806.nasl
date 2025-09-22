# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103464");
  script_version("2025-05-02T05:40:07+0000");
  script_tag(name:"last_modification", value:"2025-05-02 05:40:07 +0000 (Fri, 02 May 2025)");
  script_tag(name:"creation_date", value:"2012-04-12 10:58:35 +0200 (Thu, 12 Apr 2012)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2012-0057");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 5.x < 5.3.9 Security Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Remote attackers can exploit this issue to bypass certain
  security restrictions and create arbitrary files in the context of the application.");

  script_tag(name:"affected", value:"PHP versions 5.x prior to 5.3.9.");

  script_tag(name:"solution", value:"Update to version 5.3.9 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51806");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=54446");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=782657");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");

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

if (version_in_range(version: version, test_version: "5.0", test_version2: "5.3.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
