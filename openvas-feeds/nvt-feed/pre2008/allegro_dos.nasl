# SPDX-FileCopyrightText: 2005 Westpoint Limited
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.19304");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/1290");
  script_cve_id("CVE-2000-0470");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Allegro Software RomPager 2.10 DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Westpoint Limited");
  script_family("Denial of Service");
  script_dependencies("gb_allegro_rompager_detect.nasl");
  script_mandatory_keys("allegro/rompager/detected");

  script_tag(name:"solution", value:"Update to the latest version, or apply a patch.");

  script_tag(name:"summary", value:"Allegro Software RomPager is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"affected", value:"Version 2.10 is known to be affected.");

  script_tag(name:"insight", value:"The remote version of the product is vulnerable to a denial of
  service when sending a specifically crafted malformed request.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:allegrosoft:rompager";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "2.10" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "Update to the latest version.", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
