# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100529");
  script_version("2025-05-06T05:40:10+0000");
  script_tag(name:"last_modification", value:"2025-05-06 05:40:10 +0000 (Tue, 06 May 2025)");
  script_tag(name:"creation_date", value:"2010-03-15 13:03:19 +0100 (Mon, 15 Mar 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2010-0397");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 5.3.1 Multiple DoS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to multiple denial of service (DoS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The xmlrpc extension in PHP does not properly handle a missing
  methodName element in the first argument to the xmlrpc_decode_request function, which allows
  context-dependent attackers to cause a denial of service (NULL pointer dereference and application
  crash) and possibly have unspecified other impact via a crafted argument.");

  script_tag(name:"impact", value:"Exploiting these issues allows remote attackers to cause denial
  of service conditions in the context of an application using the vulnerable library.");

  script_tag(name:"affected", value:"PHP versions 5.2.x prior to 5.2.14 and 5.3.x prior to
  5.3.3.");

  script_tag(name:"solution", value:"Update to version 5.2.14, 5.3.3 or later.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20110611011157/http://www.securityfocus.com/bid/38708");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=573573");
  script_xref(name:"URL", value:"http://permalink.gmane.org/gmane.comp.security.oss.general/2673");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-5.php");

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

if (version_in_range_exclusive(version: version, test_version_lo: "5.2.0", test_version_up: "5.2.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.3.0", test_version_up: "5.3.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
