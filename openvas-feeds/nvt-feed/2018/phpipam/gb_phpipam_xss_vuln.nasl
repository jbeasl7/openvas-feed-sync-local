# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpipam:phpipam";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108433");
  script_version("2023-10-13T05:06:09+0000");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:09 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2018-03-16 13:46:59 +0100 (Fri, 16 Mar 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2015-6529");

  script_name("phpIPAM < 1.2 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpipam_http_detect.nasl");
  script_mandatory_keys("phpipam/detected");

  script_tag(name:"summary", value:"phpIPAM is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerabilities exist due to insufficient filtration of
  user-supplied data passed via the (1) section parameter to site/error.php or (2) ip parameter to
  site/tools/searchResults.php.");

  script_tag(name:"impact", value:"An attacker could execute arbitrary HTML and script code in a
  browser in the context of the vulnerable website.");

  script_tag(name:"affected", value:"phpIPAM version 1.1.010 and prior.");

  script_tag(name:"solution", value:"Update to version 1.2 or later.");

  script_xref(name:"URL", value:"https://phpipam.net/documents/changelog/");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/133055/phpipam-1.1.010-Cross-Site-Scripting.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/536188/100/0/threaded");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://phpipam.net");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"1.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.2", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
