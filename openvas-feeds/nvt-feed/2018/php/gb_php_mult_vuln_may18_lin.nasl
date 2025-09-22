# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813160");
  script_version("2025-09-18T05:38:39+0000");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"creation_date", value:"2018-05-02 18:02:28 +0530 (Wed, 02 May 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-19 11:15:00 +0000 (Mon, 19 Aug 2019)");

  script_cve_id("CVE-2018-10546", "CVE-2018-10547", "CVE-2018-10548", "CVE-2018-10549");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.6.36, 7.x < 7.0.30, 7.1.x < 7.1.17, 7.2.x < 7.2.5 Multiple Vulnerabilities (May 2018) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2018-10549: Out of bounds read error in 'exif_read_data' function while processing crafted
  JPG data.

  - CVE-2018-10546: An error in stream filter 'convert.iconv' which leads to infinite loop on
  invalid sequence.

  - CVE-2018-10548: An error in the LDAP module of PHP which allows a malicious LDAP server or
  man-in-the-middle attacker to crash PHP.

  - CVE-2018-10547: An error in the 'phar_do_404()' function in 'ext/phar/phar_object.c' script
  which returns parts of the request unfiltered, leading to another XSS vector. This is due to
  incomplete fix for CVE-2018-5712.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to conduct XSS
  attacks, crash PHP, conduct denial of service condition and execute arbitrary code in the context
  of the affected application.");

  script_tag(name:"affected", value:"PHP prior to version 5.6.36, 7.0.x prior to 7.0.30, 7.1.x
  prior to 7.1.17 and 7.2.x prior to 7.2.5 on Linux.");

  script_tag(name:"solution", value:"Update to version 5.6.36, 7.0.30, 7.1.17, 7.2.5 or later.");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php#5.6.36");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-7.php#7.0.30");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-7.php#7.1.17");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-7.php#7.2.5");

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

if (version_is_less(version: version, test_version: "5.6.36")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.36", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0", test_version_up: "7.0.30")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.30", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.1.0", test_version_up: "7.1.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1.17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.2.0", test_version_up: "7.2.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.2.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
