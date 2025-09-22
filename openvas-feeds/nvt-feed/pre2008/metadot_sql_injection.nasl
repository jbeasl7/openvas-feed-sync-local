# SPDX-FileCopyrightText: 2004 Noam Rathaus
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# From: JeiAr [security@gulftech.org]
# Subject: Multiple MetaDot Vulnerabilities [ All Versions ]
# Date: Friday 16/01/2004 03:11

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12024");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9439");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Multiple MetaDot Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2004 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to the latest version of Metadot.");

  script_tag(name:"summary", value:"The remote host is running Metadot, a popular open source portal software.

  Multiple vulnerabilities have been found in this product, which may allow a malicious user to inject arbitrary
  SQL commands, reveal valuable information about the server and perform Cross Site Scripting attacks.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  url = string(dir, "/metadot/index.pl?isa=Session&op=auto_login&new_user=&key='[foo]");
  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );

  if( "DBAccess::sqlSelect('DBAccess', 'uid', 'session', 'sessionid=\'\'[foo]\'')" >< res ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
