# SPDX-FileCopyrightText: 2009 Christian Eric Edjenguele
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101015");
  script_version("2024-04-17T05:05:27+0000");
  script_tag(name:"last_modification", value:"2024-04-17 05:05:27 +0000 (Wed, 17 Apr 2024)");
  script_tag(name:"creation_date", value:"2009-03-16 23:15:41 +0100 (Mon, 16 Mar 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2003-0661");
  script_name("Microsoft Windows NetBIOS Information Disclosure Vulnerability (MS03-034) - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Christian Eric Edjenguele");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("os_detection.nasl");
  script_require_udp_ports(137);
  script_mandatory_keys("Host/runs_windows");

  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/security-updates/securitybulletins/2003/ms03-034");
  script_xref(name:"URL", value:"http://www.microsoft.com/downloads/details.aspx?FamilyId=A59CC2AC-F182-4CD5-ACE7-3D4C2E3F1326&displaylang=en");
  script_xref(name:"URL", value:"http://www.microsoft.com/downloads/details.aspx?FamilyId=140CF7BE-0371-4D17-8F4C-951B76AC3024&displaylang=en");
  script_xref(name:"URL", value:"http://www.microsoft.com/downloads/details.aspx?FamilyId=1C9D8E86-5B8C-401A-88B2-4443FFB9EDC3&displaylang=en");
  script_xref(name:"URL", value:"http://www.microsoft.com/downloads/details.aspx?FamilyId=378D4B58-BF2C-4406-9D88-E6A3C4601795&displaylang=en");
  script_xref(name:"URL", value:"http://www.microsoft.com/downloads/details.aspx?FamilyId=D0564162-4EAE-42C8-B26C-E4D4D496EAD8&displaylang=en");
  script_xref(name:"URL", value:"http://www.microsoft.com/downloads/details.aspx?FamilyId=F131D63A-F74F-4CAF-95BD-D7FA37ADCF38&displaylang=en");
  script_xref(name:"URL", value:"http://www.microsoft.com/downloads/details.aspx?FamilyId=22379951-64A9-446B-AC8F-3F2F080383A9&displaylang=en");

  script_tag(name:"summary", value:"Microsoft Windows is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted NetBIOS request and checks the response.");

  script_tag(name:"insight", value:"Under certain conditions, the response to a NetBT Name Service
  query may, in addition to the typical reply, contain random data from the target system's memory.
  This data could, for example, be a segment of HTML if the user on the target system was using an
  Internet browser, or it could contain other types of data that exist in memory at the time that
  the target system responds to the NetBT Name Service query.");

  script_tag(name:"impact", value:"An attacker could seek to exploit this vulnerability by sending a
  NetBT Name Service query to the target system and then examine the response to see if it included
  any random data from that system's memory.");

  script_tag(name:"solution", value:"Microsoft has released patches to fix this issue. Please see
  the references for more information.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");

port = 137;
if( ! get_udp_port_state( port ) )
  exit( 0 );

matrix = make_array();

request = raw_string("\x7c\x54\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00",
                     "\x20\x43\x4B\x41\x41\x41\x41\x41\x41\x41\x41\x41",
                     "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41",
                     "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21",
                     "\x00\x01");

for( i = 0; i < 50; i++ ) {

  if( ! soc = open_sock_udp( port ) )
    exit( 0 );

  send( socket:soc, data:request );

  response = recv( socket:soc, length:4096, timeout:20 );
  close( soc );

  if( strlen( response ) > 58 ) {
    min = strlen( response ) - 58;
    element = substr( response, min, strlen( response ) );
    matrix[max_index(matrix)] = element;
  }

  dim = max_index( matrix ) - 1;
  if( dim > 1 ) {
    for( j = 0; j < i; j++ ) {
      if( matrix[j] != matrix[i] ) {
        security_message( port:port, proto:"udp" );
        exit( 0 );
      }
    }
  }
}

exit( 99 );
