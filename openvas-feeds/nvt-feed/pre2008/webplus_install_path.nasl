# SPDX-FileCopyrightText: 2004 David Kyger
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12074");
  script_version("2024-08-09T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-08-09 05:05:42 +0000 (Fri, 09 Aug 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_name("Talentsoft Web+ Information Disclosure Vulnerability");
  script_category(ACT_ATTACK); # nb: Direct access to a .exe file might be already seen as an attack
  script_copyright("Copyright (C) 2004 David Kyger");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.talentsoft.com/Issues/IssueDetail.wml?ID=WP197");

  script_tag(name:"solution", value:"Apply the vendor-supplied patch.");

  script_tag(name:"summary", value:"The remote host appears to be running Web+ Application Server which
  is affected by an information disclosure flaw.");

  script_tag(name:"insight", value:"The version of Web+ installed on the remote host reveals the physical
  path of the application when it receives a script file error.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/webplus.exe?script=vt_test";

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
  if( "Web+ Error Message" >< res ) {
    path = strstr( res, " '" );
    path = ereg_replace( pattern:" and.*$", replace:"", string:path );
    report = path;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 0 );
