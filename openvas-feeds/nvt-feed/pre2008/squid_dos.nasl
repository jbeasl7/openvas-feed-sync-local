# SPDX-FileCopyrightText: 2001 Adam Baldwin
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10768");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3354");
  script_cve_id("CVE-2001-0843");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Squid DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2001 Adam Baldwin");
  script_dependencies("gb_squid_http_detect.nasl");
  script_mandatory_keys("squid/detected");

  script_tag(name:"summary", value:"A problem exists in the way the remote Squid proxy server handles a
  special 'mkdir-only' PUT request, and causes denial of service to the proxy server.");

  script_tag(name:"impact", value:"An attacker may use this flaw to prevent your LAN users from accessing
  the web.");

  script_tag(name:"solution", value:"Apply the vendor released patch, for squid it is available at the
  linked references. You can also protect yourself by enabling access lists on your proxy.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( "2.3" >< vers && ( "STABLE1" >< vers || "STABLE3" >< vers ||
    "STABLE4" >< vers || "STABLE5" >< vers ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references" );
  security_message( port:port, data:report );
  exit( 0 );
}

#CHECK VERSION 2.4
if( "2.4" >< vers && ( "STABLE1" >< vers || "PRE-STABLE2" >< vers ||
   "PRE-STABLE" >< vers || "DEVEL4" >< vers || "DEVEL2" >< vers ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
