# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902555");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-08-29 16:22:41 +0200 (Mon, 29 Aug 2011)");
  script_cve_id("CVE-1999-0197");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Finger Service Unused Account Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/8378");
  script_xref(name:"URL", value:"http://www.iss.net/security_center/reference/vuln/finger-unused-accounts.htm");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("find_service.nasl", "find_service1.nasl", "find_service2.nasl");
  script_require_ports("Services/finger", 79);

  script_tag(name:"summary", value:"The finger service is prone to an information disclosure
  vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain sensitive information
  that could aid in further attacks.");

  script_tag(name:"affected", value:"GNU finger is known to be affected. Other finger implementations might be
  affected as well.");

  script_tag(name:"insight", value:"The flaw exists because the finger service displays a list of unused accounts
  for a 'finger 0@host' request.");

  script_tag(name:"solution", value:"Disable the finger service, or install a finger service or daemon that
  limits the type of information provided.");

  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(default:79, proto:"finger");

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

banner = recv(socket:soc, length:2048, timeout:5);
if(banner) {
  close(soc);
  exit(0);
}

send(socket:soc, data:string("0\r\n"));
res = recv(socket:soc, length:2048);
close(soc);
if(!res)
  exit(0);

if(strlen(res) > 150) {
  if("adm" >< res || "bin" >< res || "daemon" >< res ||
      "lp" >< res || "sys" >< res) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);
