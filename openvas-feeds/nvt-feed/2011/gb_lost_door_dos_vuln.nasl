# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801943");
  script_version("2023-10-12T05:05:32+0000");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"creation_date", value:"2011-06-02 11:54:09 +0200 (Thu, 02 Jun 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Lost Door J-Revolution Denial of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(7183);

  script_xref(name:"URL", value:"http://www.1337day.com/exploits/16203");
  script_xref(name:"URL", value:"http://donofjsr.blogspot.com/2011/03/lostdoor-j-revolution-v6.html");

  script_tag(name:"impact", value:"Successful exploitation will let remote unauthenticated attackers
  to cause a denial of service condition.");

  script_tag(name:"affected", value:"Lost Door J-Revolution version 6");

  script_tag(name:"insight", value:"The flaw is due to error in handling the message used by LastDoor
  which uses a simple clear text protocol with a delimiter.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Lost Door J-Revolution is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

ldPort = 7183 ;
if(!get_port_state(ldPort)){
  exit(0);
}

# nb: Open TCP Socket and immediately close the socket without sending any data this will trigger an exception at server side causing denial of service
soc = open_sock_tcp(ldPort);
if(!soc){
  exit(0);
}
close(soc);

sleep(5);

soc = open_sock_tcp(ldPort);
if(!soc){
  security_message(port:ldPort);
  exit(0);
}

close(soc);