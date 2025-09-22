# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108053");
  script_version("2025-05-09T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-05-09 05:40:06 +0000 (Fri, 09 May 2025)");
  script_tag(name:"creation_date", value:"2017-01-25 11:00:00 +0100 (Wed, 25 Jan 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-20 16:58:00 +0000 (Wed, 20 Jul 2022)");

  script_cve_id("CVE-2016-10158", "CVE-2016-10159", "CVE-2016-10160", "CVE-2016-10161",
                "CVE-2016-10167", "CVE-2016-10168", "CVE-2017-11147");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.6.30, 7.x < 7.0.15, 7.1.x < 7.1.1 Multiple Vulnerabilities (Jan 2017) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2016-10161: Heap out of bounds read on unserialize in finish_nested_data()

  - CVE-2016-10158: FPE when parsing a tag format

  - CVE-2016-10168: Signed Integer Overflow gd_io.c

  - CVE-2016-10167: DOS vulnerability in gdImageCreateFromGd2Ctx()

  - CVE-2017-11147: Seg fault when loading hostile phar

  - CVE-2016-10160: Memory corruption when loading hostile phar

  - CVE-2016-10159: Crash while loading hostile phar archive");

  script_tag(name:"affected", value:"PHP prior to version 5.6.30, 7.x prior to 7.0.15 and 7.1.x
  prior to 7.1.1.");

  script_tag(name:"solution", value:"Update to version 5.6.30, 7.0.15, 7.1.1 or later.");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-7.php");
  script_xref(name:"URL", value:"http://bugs.php.net/73825");
  script_xref(name:"URL", value:"http://bugs.php.net/73737");
  script_xref(name:"URL", value:"http://bugs.php.net/73869");
  script_xref(name:"URL", value:"http://bugs.php.net/73868");
  script_xref(name:"URL", value:"http://bugs.php.net/73773");
  script_xref(name:"URL", value:"http://bugs.php.net/73768");
  script_xref(name:"URL", value:"http://bugs.php.net/73764");

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

if (version_is_less(version: version, test_version: "5.6.30")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6.30", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0.0", test_version_up: "7.0.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.1.0", test_version_up: "7.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
