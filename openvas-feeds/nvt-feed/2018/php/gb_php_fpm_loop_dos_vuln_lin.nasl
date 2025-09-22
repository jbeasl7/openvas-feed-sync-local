# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812520");
  script_version("2025-09-18T05:38:39+0000");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-02-20 18:02:59 +0530 (Tue, 20 Feb 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-19 00:15:00 +0000 (Wed, 19 Feb 2020)");

  script_cve_id("CVE-2015-9253");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 5.x < 7.1.20, 7.2.x < 7.2.8, 7.3.0alpha1 < 7.3.0alpha3 DoS Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PHP is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the php-fpm master process restarts a
  child process in an endless loop when using program execution functions with a non-blocking STDIN
  stream.");

  script_tag(name:"impact", value:"Successfully exploitation will allow an attacker to consume
  100% of the CPU, and consume disk space with a large volume of error logs, as demonstrated by an
  attack by a customer of a shared-hosting facility.");

  script_tag(name:"affected", value:"PHP versions 5.x, 7.0.x, 7.1.x prior to 7.1.20, 7.2.x prior
  to 7.2.8 and 7.3.x prior to 7.3.0alpha3 on Linux.");

  script_tag(name:"solution", value:"Update to version 7.1.20, 7.2.8, 7.3.0alpha3 or later.");

  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=73342");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=70185");
  script_xref(name:"URL", value:"https://github.com/php/php-src/pull/3287");
  script_xref(name:"URL", value:"https://www.futureweb.at/security/CVE-2015-9253");

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

if (version_in_range_exclusive(version: version, test_version_lo: "5.0.0", test_version_up: "7.1.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1.20", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.2.0", test_version_up: "7.2.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.3.0alpha1", test_version_up: "7.3.0alpha3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.3.0alpha3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
