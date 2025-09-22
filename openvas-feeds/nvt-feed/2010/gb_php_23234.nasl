# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100600");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2010-04-23 13:12:25 +0200 (Fri, 23 Apr 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2007-1825");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 4.x < 4.4.5, 5.x < 5.2.1 Buffer Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to a buffer overflow vulnerability because the
  application fails to perform boundary checks before copying user-supplied data to insufficiently
  sized memory buffers.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary machine
  code in the context of the affected webserver. Failed exploit attempts will likely crash the
  webserver, denying service to legitimate users.");

  script_tag(name:"affected", value:"PHP versions 4.x prior to 4.4.5 and 5.x prior to 5.2.1.");

  script_tag(name:"solution", value:"Update to version 4.4.5, 5.2.1 or later.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20130318021556/http://www.securityfocus.com/bid/23234");
  script_xref(name:"URL", value:"http://www.php-security.org/MOPB/MOPB-40-2007.html");

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

if (version_in_range_exclusive(version: version, test_version_lo: "4.0.0", test_version_up: "4.4.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.0.0", test_version_up: "5.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
