# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804682");
  script_version("2025-05-06T05:40:10+0000");
  script_tag(name:"last_modification", value:"2025-05-06 05:40:10 +0000 (Tue, 06 May 2025)");
  script_tag(name:"creation_date", value:"2014-07-18 14:56:10 +0530 (Fri, 18 Jul 2014)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2014-4670", "CVE-2014-4698");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP 5.5.x < 5.5.15 Multiple Use After Free Vulnerabilities (Jul 2014)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to multiple use after free vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An use-after-free error exists in the ext/spl/spl_dllist.c
  file in the SPL component.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct
  denial of service attacks or possibly have some other unspecified impact.");

  script_tag(name:"affected", value:"PHP version 5.x through 5.5.14.");

  script_tag(name:"solution", value:"Update to version 5.5.15 or later.");

  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=67539");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68511");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68513");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=67538");
  script_xref(name:"URL", value:"http://git.php.net/?p=php-src.git;a=patch;h=df78c48354f376cf419d7a97f88ca07d572f00fb");
  script_xref(name:"URL", value:"http://git.php.net/?p=php-src.git;a=patch;h=22882a9d89712ff2b6ebc20a689a89452bba4dcd");

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

if (version_in_range(version: version, test_version: "5.5.0", test_version2: "5.5.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
