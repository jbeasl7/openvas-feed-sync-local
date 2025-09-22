# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:isc:bind";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100458");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-01-20 19:30:24 +0100 (Wed, 20 Jan 2010)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0097", "CVE-2010-0290", "CVE-2010-0382");
  script_name("ISC BIND DNSSEC Bogus NXDOMAIN Response Remote Cache Poisoning Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_isc_bind_consolidation.nasl");
  script_mandatory_keys("isc/bind/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37865");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/360341");
  script_xref(name:"URL", value:"https://kb.isc.org/docs/aa-00932");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"ISC BIND is prone to a remote cache-poisoning vulnerability.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to manipulate cache data,
  potentially facilitating man-in-the-middle, site-impersonation, or denial-of-service attacks.");

  script_tag(name:"affected", value:"Versions prior to the following are vulnerable:

  BIND 9.4.3-P5 BIND 9.5.2-P2 BIND 9.6.1-P3");

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
  if( version_is_less( version:version, test_version: "9.4.3p5" ) ) {
    fix = "9.4.3-P5";
    VULN = TRUE;
  }
}

else if( version =~ "^9\.5" ) {
  if( version_is_less( version:version, test_version:"9.5.2p2" ) ) {
    fix = "9.5.3-P2";
    VULN = TRUE;
  }
}

else if( version =~ "^9\.6" ) {
  if( version_is_less( version:version, test_version:"9.6.1p3" ) ) {
    fix = "9.6.1-P3";
    VULN = TRUE;
  }
}

if( VULN ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix, install_path:location );
  security_message( data:report, port:port, proto:proto );
  exit( 0 );
}

exit( 99 );
