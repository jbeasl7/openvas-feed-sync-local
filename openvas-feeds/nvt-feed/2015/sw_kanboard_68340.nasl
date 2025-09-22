# SPDX-FileCopyrightText: 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:kanboard:kanboard";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111063");
  script_version("2023-07-13T05:06:09+0000");
  script_tag(name:"last_modification", value:"2023-07-13 05:06:09 +0000 (Thu, 13 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-12-04 13:00:00 +0100 (Fri, 04 Dec 2015)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2014-3920");

  script_name("Kanboard < 1.0.6 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_kanboard_http_detect.nasl");
  script_mandatory_keys("kanboard/detected");

  script_tag(name:"summary", value:"Kanboard is prone to a cross-site request forgery (CSRF)
  vulnerability because it does not properly validate HTTP requests.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Exploiting this issue may allow a remote attacker to perform
  certain unauthorized actions. This may lead to further attacks.");

  script_tag(name:"affected", value:"Kanboard prior to version 1.0.6.");

  script_tag(name:"solution", value:"Update to version 1.0.6 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68340");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/532619/100/0/threaded");
  script_xref(name:"URL", value:"http://kanboard.net/news/version-1.0.6");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
path = infos["location"];

if( version_is_less( version:version, test_version:"1.0.6" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.0.6", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
