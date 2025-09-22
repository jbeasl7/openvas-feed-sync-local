# SPDX-FileCopyrightText: 2005 Charles Thier
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18413");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-1999-0507", "CVE-1999-0508");
  script_name("Allied Telesyn Router/Switch Default Password (HTTP)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2005 Charles Thier");
  script_family("Default Accounts");
  script_dependencies("gb_get_http_banner.nasl", "gb_default_credentials_options.nasl");
  script_mandatory_keys("ATR-HTTP/banner");
  script_require_ports("Services/www", 80);
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"solution", value:"Connect to this Router/Switch and change the default password.");

  script_tag(name:"summary", value:"The Allied Telesyn Router/Switch has the default password set.");

  script_tag(name:"impact", value:"The attacker could use this default password to gain remote access
  to the switch or router. This password could also be potentially used to gain other sensitive
  information about your network from the device.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);
banner = http_get_remote_headers(port:port);
if(!banner || "Server: ATR-HTTP-Server" >!< banner)
  exit(0);

url = "/";
res = http_get_cache(item:url, port:port);
if(!res)
  exit(0);

if( egrep( pattern:"^HTTP/1\.[01] 401", string:res ) ) {

  # nb: Just for the request below
  req = http_get(item:url, port:port);
  req -= string("\r\n\r\n");
  # nb: Credentials manager:friend
  req += string("\r\nAuthorization: Basic bWFuYWdlcjpmcmllbmQ=\r\n\r\n");
  res = http_keepalive_send_recv(port:port, data:req);
  if(!res)
    exit(0);

  if( egrep( pattern:"^HTTP/1\.[01] 200", string:res) ) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);
