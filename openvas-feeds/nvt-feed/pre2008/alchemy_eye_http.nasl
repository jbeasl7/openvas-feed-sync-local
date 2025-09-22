# SPDX-FileCopyrightText: 2001 HD Moore & Drew Hintz
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10818");
  script_version("2023-07-07T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-07-07 05:05:26 +0000 (Fri, 07 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-0871");
  script_name("Alchemy Eye HTTP Command Execution");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2001 HD Moore & Drew Hintz");
  script_family("Web application abuses");
  script_dependencies("gb_alchemy_eye_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("alchemy_eye/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/243404");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3599");

  script_tag(name:"summary", value:"Alchemy Eye and Alchemy Network Monitor are network management
  tools for Microsoft Windows. The product contains a built-in HTTP
  server for remote monitoring and control. This HTTP server allows
  arbitrary commands to be run on the server by a remote attacker.");

  script_tag(name:"solution", value:"Either disable HTTP access in Alchemy Eye, or require
  authentication for Alchemy Eye. Both of these can be set in the Alchemy Eye preferences.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

foreach dir( make_list( "/PRN", "/NUL", "" ) ) {

  url = string("/cgi-bin", dir, "/../../../../../../../../WINNT/system32/net.exe");

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );
  if(!res)
    continue;

  if( "ACCOUNTS | COMPUTER" >< res ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
