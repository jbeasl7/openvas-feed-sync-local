# SPDX-FileCopyrightText: 2005 Digital Defense Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11317");
  script_version("2023-07-07T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-07-07 05:05:26 +0000 (Fri, 07 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2002-1048");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("HP JetDirect EWS Password Discovery (SNMP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2005 Digital Defense Inc.");
  script_family("General");
  script_dependencies("gb_hp_printer_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("hp/printer/snmp/detected", "hp/printer/http/detected");

  script_tag(name:"summary", value:"The remote HP JetDirect printer might expose a password for the
  embedded web server access.");

  script_tag(name:"insight", value:"This script attempts to obtain the password of the remote HP
  JetDirect web server (available in some printers) by requesting the OID:

  .1.3.6.1.4.1.11.2.3.9.1.1.13.0

  of the remote printer.");

  script_tag(name:"impact", value:"An attacker may use this flaw to gain administrative access on
  that printer.

  See the references for more information.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/313714/2003-03-01/2003-03-07/0");
  script_xref(name:"URL", value:"http://www.iss.net/security_center/static/9693.php");
  script_xref(name:"URL", value:"http://www.iss.net/issEn/delivery/xforce/alertdetail.jsp?id=advise15");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("snmp_func.inc");

#--------------------------------------------------------------------#
# Forges an SNMP GET packet                                          #
#--------------------------------------------------------------------#
function get( community, object ) {

  local_var len, tot_len, packet, object_len, pack_len, community, object;

  len = strlen( community );
  len = len % 256;

  tot_len = 23 + strlen( community ) + strlen( object );
  packet = raw_string( 0x30, tot_len, 0x02, 0x01, 0x00, 0x04, len );
  object_len = strlen( object ) + 2;

  pack_len = 16 + strlen( object );
  packet = packet + community +
           raw_string( 0xA0, pack_len, 0x02, 0x04, 0x5e, 0xa4, 0x3f, 0x0c, 0x02, 0x01, 0x00, 0x02,
           0x01, 0x00, 0x30, object_len ) + object + raw_string( 0x05, 0x00 );
  return( packet );
}

#--------------------------------------------------------------------#
# Checks if JetDirect is vulnerable                                  #
#--------------------------------------------------------------------#
function vulnerable( httpport ) {

  local_var httpport, url, reply, sndReq, rcvRes;

  url = "/hp/jetdirect/tcp_param.htm";
  reply = FALSE;

  sndReq = http_get( item:url, port:httpport );
  rcvRes = http_keepalive_send_recv( port:httpport, data:sndReq, bodyonly:FALSE );

  #if firmware is current, url will give a 200 or a 401
  if( rcvRes =~ "HTTP/1\.. 200" || rcvRes =~ "HTTP/1\.. 401" ) return( reply );

  #if 404 returned, old firmware present
  if( rcvRes =~ "HTTP/1\.. 404" ) {

    url = "/";

    rcvRes = http_get_cache( item:url, port:httpport );

    #if / gives 404, web server is disabled - gives 404 for any request
    if( rcvRes !~ "HTTP/1\.. 404" ) {
      reply = TRUE;
    }
  }
  return( reply );
}

passwordless = 0;
password = string("");
equal_sign = raw_string( 0x3D );
nothing = raw_string( 0x00 );

snmpport = snmp_get_port( default:161 );
community = snmp_get_community( port:snmpport );
if( ! community ) exit( 0 );

httpport = 80;
if( ! get_port_state( httpport ) ) exit( 0 );
if( ! ( vulnerable( httpport:httpport ) ) ) exit( 0 );

if( ! get_udp_port_state( snmpport ) ) exit( 0 );
soc = open_sock_udp( snmpport );
if( ! soc ) exit( 0 );

MIB = raw_string( 0x30, 0x11, 0x06,
                  0x0D, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x0B, 0x02,
                  0x03, 0x09, 0x01, 0x01, 0x0D, 0x00 );

req = get( community:community, object:MIB );

send( socket:soc, data:req );
r = recv( socket:soc, length:1025 );

if( ! strlen( r ) ) exit( 0 );

len = strlen( r );

start = 0;
for( i = 0; ( i + 2 ) < len; i++ ) {

  #look for preamble to password
  if( ord( r[i] ) == 0x04 ) {
    if( ord( r[i + 1] ) == 0x82 ) {
      if( ord( r[i + 2] ) == 0x01 ) {
        start = i + 4;
        i = len;
        #found password, check if blank
        if( r[start] == nothing ) {
          if( r[start + 1] == nothing ) {
            if(r[start + 2] == nothing) {
              if( r[start + 3] == nothing ) {
                passwordless = 1;
              }
            }
          }
        }
      }
    }
  }
}

#some printers respond with nothing but 04 00 when passwordless
if( start == 0 && len >= 2 ) {
  if( ( ord( r[len - 1] ) == 0x00 ) && ( ord( r[len - 2] ) == 0x04 ) ) {
    passwordless = 1;
  }
}

if( ! ( passwordless ) ) {
  password = string("The password is ");
  #password format is password=108;  here we look for the = as the end of the passwd
  for( i = start; i < len; i++ ) {
    if( r[i] == equal_sign ) {
      i = len;
    } else {
      password = password + r[i];
    }
  }
}

report = "";

if( strlen( password ) > 1 ) {
  report = "It was possible to obtain the remote printer embedded web server ";
  report += " password ('" + password + "') by querying the SNMP OID .1.3.6.1.4.1.11.2.3.9.1.1.13.0.";
  report += '\n\nAn attacker may use this flaw to gain administrative privileges on this printer';
} else {
  if( passwordless ) {
    report = "It was possible to obtain the remote printer embedded web server ";
    report += "password by querying the SNMP OID .1.3.6.1.4.1.11.2.3.9.1.1.13.0 and we ";
    report += "discovered that the remote printer has no password set !";
    report += '\n\nAn attacker may use this flaw to gain administrative privileges on this printer';
  }
}

if( report != "" ) {
  security_message( port:snmpport, data:report, protocol:"udp" );
  exit( 0 );
}

exit( 99 );
