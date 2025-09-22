# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801860");
  script_version("2025-05-06T05:40:10+0000");
  script_tag(name:"last_modification", value:"2025-05-06 05:40:10 +0000 (Tue, 06 May 2025)");
  script_tag(name:"creation_date", value:"2011-03-10 13:33:28 +0100 (Thu, 10 Mar 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2011-0420");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 5.3.5 NULL Pointer Dereference DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to a NULL pointer dereference denial of service
  (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A NULL pointer dereference in the 'grapheme_extract()'
  function in the Internationalization extension (Intl) for ICU allows context-dependent attackers
  to cause a denial of service via an invalid size argument.");

  script_tag(name:"impact", value:"Successful exploitation could allows context-dependent
  attackers to cause a denial of service.");

  script_tag(name:"affected", value:"PHP version 5.3.5.");

  script_tag(name:"solution", value:"Update to version 5.3.6 or later.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16182");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46429");
  script_xref(name:"URL", value:"http://securityreason.com/achievement_securityalert/94");
  script_xref(name:"URL", value:"http://svn.php.net/viewvc/php/php-src/trunk/ext/intl/grapheme/grapheme_string.c?r1=306449&r2=306448&pathrev=306449");
  script_xref(name:"URL", value:"http://svn.php.net/viewvc?view=revision&revision=306449");

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

if (version_is_equal(version: version, test_version: "5.3.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
