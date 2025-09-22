# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802323");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-12 14:44:50 +0200 (Fri, 12 Aug 2011)");
  script_cve_id("CVE-1999-0259");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Cfingerd 'search' Command Information Disclosure Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("find_service.nasl", "find_service1.nasl", "find_service2.nasl");
  script_require_ports("Services/finger", 79);

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/1811");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/1997_2/0328.html");

  script_tag(name:"summary", value:"Cfingerd is prone to an information disclosure vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to obtain sensitive information
  that could aid in further attacks.");

  script_tag(name:"affected", value:"Cfingerd version 1.2.2 is known to be affected. Other versions or finger
  implementations might be affected as well.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the finger service which allows to list
  all usernames on the host via the 'search.**' command.");

  script_tag(name:"solution", value:"Update to Cfingerd version 1.2.3 or later.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

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

send(socket:soc, data:string("search.**\r\n"));
res = recv(socket:soc, length:2048);
close(soc);
if(!res)
  exit(0);

if("Finger" >< res && "Username" >< res && "root" >< res) {
  security_message(port:port);
  exit(0);
}

exit(99);
