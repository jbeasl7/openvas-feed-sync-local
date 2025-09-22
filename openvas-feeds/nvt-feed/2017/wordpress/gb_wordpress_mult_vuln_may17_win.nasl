# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811045");
  script_version("2024-02-08T05:05:59+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-05-19 10:44:26 +0530 (Fri, 19 May 2017)");
  script_name("WordPress Multiple Vulnerabilities (May 2017) - Windows");

  script_tag(name:"summary", value:"WordPress is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An insufficient redirect validation in the HTTP class.

  - An improper handling of post meta data values in the XML-RPC API.

  - The lack of capability checks for post meta data in the XML-RPC API.

  - A cross site request forgery (CSRF)  vulnerability in the filesystem
    credentials dialog.

  - A cross-site scripting (XSS) vulnerability when attempting to upload very
    large files.

  - A cross-site scripting (XSS) vulnerability related to the Customizer.");

  script_tag(name:"impact", value:"Successfully exploiting will allow remote
  attacker to conduct cross site request forgery (CSRF) attacks, cross-site
  scripting (XSS) attacks and have other some unspecified impact.");

  script_tag(name:"affected", value:"WordPress versions 4.7.4 and prior on
  Windows.");

  script_tag(name:"solution", value:"Update to WordPress version 4.7.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://wordpress.org/news/2017/05/wordpress-4-7-5");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl", "gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/detected", "Host/runs_windows");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!wpPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!wpVer = get_app_version(cpe:CPE, port:wpPort)){
  exit(0);
}

if(version_is_less(version:wpVer, test_version:"4.7.5"))
{
  report = report_fixed_ver(installed_version:wpVer, fixed_version:"4.7.5");
  security_message(data:report, port:wpPort);
  exit(0);
}
