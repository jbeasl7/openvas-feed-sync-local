# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108507");
  script_version("2025-09-18T05:38:39+0000");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-12-11 09:08:47 +0100 (Tue, 11 Dec 2018)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-18 18:12:00 +0000 (Mon, 18 Apr 2022)");

  script_cve_id("CVE-2018-19395", "CVE-2018-19396", "CVE-2018-19518", "CVE-2018-20783");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 5.6.x < 5.6.38, 7.x < 7.0.33, 7.1.x < 7.1.25, 7.2.x < 7.2.13 Multiple Vulnerabilities (Dec 2018) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PHP is prone to multiple security vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2018-19518: The imap_open functions which allows to run arbitrary shell commands via mailbox
  parameter.

  - CVE-2018-20783: Heap Buffer Overflow in phar_parse_pharfile.

  - CVE-2018-19396: ext/standard/var_unserializer.c allows attackers to cause a denial of service
  (application crash) via an unserialize call for the com, dotnet, or variant class.

  - CVE-2018-19395: Denial of service because com and com_safearray_proxy return NULL in
  com_properties_get in ext/com_dotnet/com_handlers.c, as demonstrated by a serialize call on
  COM('WScript.Shell').");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  remote code on the affected application/system and/or cause a cause a denial of service.");

  script_tag(name:"affected", value:"PHP versions 5.6.x prior to 5.6.39, 7.0.x prior to 7.0.33,
  7.1.x prior to 7.1.25 and 7.2.x prior to 7.2.13.");

  script_tag(name:"solution", value:"Update to version 5.6.39, 7.0.33, 7.1.25, 7.2.13, 7.3.0 or
  later.");

  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=76428");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=77153");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=77160");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=77143");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/106018");
  script_xref(name:"URL", value:"https://github.com/Bo0oM/PHP_imap_open_exploit/blob/master/exploit.php");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/45914/");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2018/11/22/3");

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

if (version_in_range_exclusive(version: version, test_version_lo: "5.6.0", test_version_up: "5.6.39")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.39", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0", test_version_up: "7.0.33")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.33", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.1.0", test_version_up: "7.1.25")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1.25", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.2.0", test_version_up: "7.2.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
