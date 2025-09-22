# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809338");
  script_version("2025-09-18T05:38:39+0000");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-10-03 12:09:46 +0530 (Mon, 03 Oct 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-07 20:00:00 +0000 (Thu, 07 Mar 2019)");

  script_cve_id("CVE-2016-7568", "CVE-2016-9137");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.6.27, 7.x < 7.0.12 Multiple DoS Vulnerabilities (Oct 2016) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PHP is prone to multiple denial of service (DoS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Integer Overflow in gdImageWebpCtx of gd_webp.c

  - Use After Free in PHP7 unserialize()");

  script_tag(name:"impact", value:"Successfully exploiting these issues allows a remote attacker
  to cause a DoS, or possibly have unspecified other impact.");

  script_tag(name:"affected", value:"PHP prior to version 5.6.27 and 7.0.x through 7.0.11.");

  script_tag(name:"solution", value:"Update to version 5.6.27, 7.0.12 or later.");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93184");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93577");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-7.php");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2016/q3/639");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=73003");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=73147");

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

if (version_is_less(version: version, test_version: "5.6.27")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.27", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0", test_version_up: "7.0.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.12", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
