# SPDX-FileCopyrightText: 2004 Noam Rathaus
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.13644");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Apache HTTP Server 'mod_rootme' Backdoor");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 Noam Rathaus");
  script_family("Malware");
  script_dependencies("gb_apache_http_server_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("apache/http_server/http/detected");

  script_tag(name:"solution", value:"- Remove the mod_rootme module from httpd.conf/modules.conf

  - Consider reinstalling the computer, as it is likely to have been compromised by an intruder");

  script_tag(name:"summary", value:"The remote system appears to be running the mod_rootme module,
  this module silently allows a user to gain a root shell access to the machine via HTTP requests.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

host = http_host_name(port:port);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

# Syntax for this Trojan is essential... normal requests won't work...
# We need to emulate a netcat, slow sending, single line each time, unlike HTTP that can
# receive everything as a block
send(socket:soc, data:string("GET root HTTP/1.0\n",
                             "Host: ", host,"\r\n"));
sleep(1);
send(socket:soc, data:string("\n"));
sleep(1);
res_vx = recv(socket:soc, length:1024);
if(!res_vx) {
  close(soc);
  exit(0);
}

send(socket:soc, data:string("id\r\n",
                             "Host: ", host, "\r\n"));
res = recv(socket:soc, length:1024);
if(!res) {
  close(soc);
  exit(0);
}

if(ereg(pattern:"^uid=[0-9]+\(root\)", string:res) && ereg(pattern:"^rootme-[0-9].[0-9] ready", string:res_vx)) {
  send(socket:soc, data:string("exit\r\n",
                               "Host: ", host, "\r\n")); # If we don't exit we can cause Apache to crash
  close(soc);
  security_message(port:port);
  exit(0);
}

close(soc);
exit(99);
