# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zope:zope";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800064");
  script_version("2023-10-06T05:06:29+0000");
  script_tag(name:"last_modification", value:"2023-10-06 05:06:29 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"creation_date", value:"2008-11-21 14:18:03 +0100 (Fri, 21 Nov 2008)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2008-5102");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zope 2.x - 2.11.2 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_zope_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("zope/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Zope is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Zope server allows improper strings to be passed via certain
  raise and import commands.");

  script_tag(name:"impact", value:"Successful exploitation allows remote authenticated users to
  cause denial of service or resource exhaustion.");

  script_tag(name:"affected", value:"Zope version 2.x through 2.11.2 on Linux.");

  script_tag(name:"solution", value:"Update to version 2.11.3 or later.");

  script_xref(name:"URL", value:"http://www.zope.org/advisories/advisory-2008-08-12");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32267");
  script_xref(name:"URL", value:"http://www.zope.org/Products/Zope/Hotfix-2008-08-12/README.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version:"2.0", test_version2:"2.11.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.11.3", install_path: location );
  security_message(data: report, port: port);
  exit( 0 );
}

exit( 99 );
