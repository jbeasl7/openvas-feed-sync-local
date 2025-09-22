# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:cisco:email_security_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105339");
  script_cve_id("CVE-2015-4236");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_version("2024-06-28T05:05:33+0000");

  script_name("Cisco AsyncOS for Email Security Appliance Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75703");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=39785");

  script_tag(name:"impact", value:"An attacker can exploit this issue to cause an affected device to become unresponsive,
resulting in a denial-of-service condition.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to improper handling of packets sent at high rate to an affected system that is configured for clustering.
An unauthenticated, remote attacker could exploit this vulnerability by sending packets to the target system at a high rate. An exploit could allow the attacker to cause
the affected system to become unresponsive on the clustering and SSH configured ports, resulting in a DoS condition.");

  script_tag(name:"solution", value:"Updates are available. Please see the vendor advisory for more information.");
  script_tag(name:"summary", value:"Cisco AsyncOS for Email Security Appliance is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"affected", value:"This issue is tracked by Cisco Bug IDs CSCur13704, CSCuq05636, CSCuv43307, and CSCuv99383.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2015-09-01 11:09:10 +0200 (Tue, 01 Sep 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_cisco_esa_version.nasl");
  script_mandatory_keys("cisco_esa/installed");
  exit(0);
}

include("host_details.inc");

if( ! vers = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list( "8.5.6-073","8.5.6-074","9.0.0-461","9.1.0-101","9.6.0-042" );

foreach af ( affected )
{
  if( vers == af )
  {
    report = 'Installed version: ' + vers + '\n' +
             'Fixed version:     See vendor advisory';
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );
