# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:cisco:email_security_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105352");
  script_cve_id("CVE-2015-6285");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_version("2023-07-25T05:05:58+0000");

  script_name("Cisco Email Security Appliance Format String Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/bugsearch/bug/CSCug21497");

  script_tag(name:"impact", value:"An unauthenticated, remote attacker could exploit this vulnerability to cause a DoS condition or partial memory override on the affected device.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to improper validation of string input in the web application. An attacker could exploit this by sending a crafted HTTP request
to the affected device. An exploit could allow the attacker to impact the integrity and availability of services and data of the device including a partial DoS condition.");

  script_tag(name:"solution", value:"See the vendor advisory for more information.");
  script_tag(name:"summary", value:"Cisco Email Security Appliance contains a vulnerability that could allow an unauthenticated, remote attacker to cause a denial of service condition on the affected device. Updates are not available.");
  script_tag(name:"affected", value:"Cisco Email Security Appliance 7.6.0-000/8.0.0-609");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-09-11 12:20:50 +0200 (Fri, 11 Sep 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_cisco_esa_version.nasl");
  script_mandatory_keys("cisco_esa/installed");
  exit(0);
}

include("host_details.inc");

if( ! vers = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list( "7.6.0","7.6.0-000","8.0.0-609" );

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

