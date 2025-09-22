# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:isc:bind";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100362");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-11-25 11:49:08 +0100 (Wed, 25 Nov 2009)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-4022");
  script_name("ISC BIND DNSSEC Query Response Additional Section Remote Cache Poisoning Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("gb_isc_bind_consolidation.nasl");
  script_mandatory_keys("isc/bind/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37118");
  script_xref(name:"URL", value:"https://kb.isc.org/docs/aa-00931");

  script_tag(name:"impact", value:"An attacker may leverage this issue to manipulate cache data,
  potentially facilitating man-in-the-middle, site-impersonation, or denial-of-service attacks.");

  script_tag(name:"affected", value:"Versions prior to the following are vulnerable:

  BIND 9.4.3-P4 BIND 9.5.2-P1 BIND 9.6.1-P2.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"ISC BIND is prone to a remote cache-poisoning vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_full( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
proto = infos["proto"];
location = infos["location"];

if( version =~ "^9\.[0-4]+" ) {
  if( version_is_less( version:version, test_version:"9.4.3p4" ) ) {
    fix = "9.4.3-P4";
    VULN = TRUE;
  }
}

else if( version =~ "^9\.5" ) {
  if( version_is_less( version:version, test_version:"9.5.2p1" ) ) {
    fix = "9.5.2-P1";
    VULN = TRUE;
  }
}

else if( version =~ "^9\.6" ) {
  if( version_is_less( version:version, test_version:"9.6.1p2" ) ) {
    fix = "9.6.1-P2";
    VULN = TRUE;
  }
}

if( VULN ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix, install_path:location );
  security_message( data:report, port:port, proto:proto );
  exit( 0 );
}

exit( 99 );
