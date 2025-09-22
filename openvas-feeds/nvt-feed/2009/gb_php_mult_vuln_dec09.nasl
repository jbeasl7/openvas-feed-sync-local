# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801060");
  script_version("2025-05-06T05:40:10+0000");
  script_tag(name:"last_modification", value:"2025-05-06 05:40:10 +0000 (Tue, 06 May 2025)");
  script_tag(name:"creation_date", value:"2009-12-04 14:17:59 +0100 (Fri, 04 Dec 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2009-2626", "CVE-2009-4018");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 5.2.11, 5.3.x < 5.3.1 Multiple Vulnerabilities (Dec 2009)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2009-2626: Error in 'zend_restore_ini_entry_cb()' function in 'zend_ini.c', which allows
  attackers to obtain sensitive information.

  - CVE-2009-4018: Error in 'proc_open()' function in 'ext/standard/proc_open.c' that does not
  enforce the 'safe_mode_allowed_env_vars' and 'safe_mode_protected_env_vars' directives, which
  allows attackers to execute programs with an arbitrary environment via the env parameter.");

  script_tag(name:"impact", value:"Successful exploitation could allow local attackers to bypass
  certain security restrictions and cause denial of service.");

  script_tag(name:"affected", value:"PHP versions prior to 5.2.11 and 5.3.x prior to 5.3.1.");

  script_tag(name:"solution", value:"Update to version 5.2.11, 5.3.1 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37482");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36009");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37138");
  script_xref(name:"URL", value:"http://bugs.php.net/bug.php?id=49026");
  script_xref(name:"URL", value:"http://securityreason.com/achievement_securityalert/65");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/11/23/15");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-5.php#PHP_5_2");

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

if (version_is_less(version: version, test_version: "5.2.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.3.0", test_version_up: "5.3.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
