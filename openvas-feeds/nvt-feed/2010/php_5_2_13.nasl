# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100511");
  script_version("2025-05-06T05:40:10+0000");
  script_tag(name:"last_modification", value:"2025-05-06 05:40:10 +0000 (Tue, 06 May 2025)");
  script_tag(name:"creation_date", value:"2010-02-27 19:39:22 +0100 (Sat, 27 Feb 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2010-1128", "CVE-2010-1129");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.2.13 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2010-1128: The Linear Congruential Generator (LCG) does not provide the expected entropy,
  which makes it easier for context-dependent attackers to guess values that were intended to be
  unpredictable

  - CVE-2010-1129: The safe_mode implementation does not properly handle directory pathnames that
  lack a trailing slash character, which allows context-dependent attackers to bypass intended
  access restrictions via vectors related to use of the tempnam function");

  script_tag(name:"affected", value:"PHP prior to version 5.2.13.");

  script_tag(name:"solution", value:"Update to version 5.2.13 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38182");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38431");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38430");
  script_xref(name:"URL", value:"http://securityreason.com/achievement_securityalert/82");
  script_xref(name:"URL", value:"http://www.php.net/releases/5_2_13.php");
  script_xref(name:"URL", value:"http://svn.php.net/viewvc/php/php-src/branches/PHP_5_2/ext/session/session.c?r1=293036&r2=294272");
  script_xref(name:"URL", value:"http://svn.php.net/viewvc/php/php-src/branches/PHP_5_3/ext/session/session.c?r1=293036&r2=294272");

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

if (version_is_less(version: version, test_version: "5.2.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
