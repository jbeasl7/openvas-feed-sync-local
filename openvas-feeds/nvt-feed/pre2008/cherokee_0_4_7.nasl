# SPDX-FileCopyrightText: 2004 David Maciejak
# SPDX-FileCopyrightText: Tenable Network Security
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15618");
  script_version("2023-11-14T05:06:15+0000");
  script_tag(name:"last_modification", value:"2023-11-14 05:06:15 +0000 (Tue, 14 Nov 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-2171");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9496");
  script_xref(name:"OSVDB", value:"3707");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Cross-Site Scripting in Cherokee Error Pages");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Maciejak & Copyright (C) Tenable Network Security");
  script_family("Web Servers");
  script_dependencies("gb_cherokee_http_detect.nasl");
  script_mandatory_keys("cherokee/detected");

  script_tag(name:"solution", value:"Upgrade to Cherokee 0.4.8 or newer.");

  script_tag(name:"summary", value:"The remote Cherokee web server is vulnerable to a cross-site scripting issue
  due to lack of sanitization in returned error pages.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

CPE = "cpe:/a:cherokee-project:cherokee";

include( "host_details.inc" );
include( "version_func.inc" );

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "0.4.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "0.4.8", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
