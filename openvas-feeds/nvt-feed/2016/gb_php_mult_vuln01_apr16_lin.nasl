# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807807");
  script_version("2025-09-18T05:38:39+0000");
  script_tag(name:"last_modification", value:"2025-09-18 05:38:39 +0000 (Thu, 18 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-04-22 17:47:06 +0530 (Fri, 22 Apr 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");

  script_cve_id("CVE-2016-3141", "CVE-2016-3142");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.5.33, 5.6.x < 5.6.19 Multiple Vulnerabilities (Apr 2016) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Use-after-free error in wddx.c script in the WDDX extension in PHP

  - Error in the phar_parse_zipfile function in zip.c script in the PHAR extension in PHP.");

  script_tag(name:"impact", value:"Successfully exploiting these issues allow remote attackers to
  gain access to potentially sensitive information and conduct a denial of service (memory
  corruption and application crash).");

  script_tag(name:"affected", value:"PHP prior to version 5.5.33 and 5.6.x prior to 5.6.19 on
  Linux.");

  script_tag(name:"solution", value:"Update to PHP version 5.5.33, 5.6.19 or later.");

  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=71587");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=71498");
  script_xref(name:"URL", value:"https://secure.php.net/ChangeLog-5.php");

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

if (version_is_less(version: version, test_version: "5.5.33")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.33", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.6.0", test_version_up: "5.6.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.19", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
