# SPDX-FileCopyrightText: 2005 George A. Theall
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mailenable:mailenable";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15852");
  script_version("2023-05-11T09:09:33+0000");
  script_tag(name:"last_modification", value:"2023-05-11 09:09:33 +0000 (Thu, 11 May 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2004-2501");
  script_xref(name:"OSVDB", value:"12135");
  script_xref(name:"OSVDB", value:"12136");

  script_name("MailEnable Multiple IMAP Buffer Overflow Vulnerabilities (Nov 2004) - Active Check");

  script_category(ACT_DENIAL);

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_copyright("Copyright (C) 2005 George A. Theall");
  script_family("Denial of Service");
  script_dependencies("gb_mailenable_consolidation.nasl");
  script_mandatory_keys("mailenable/imap/detected");
  script_require_ports("Services/imap", 143);

  script_tag(name:"summary", value:"MailEnable is prone to multiple buffer overflow vulnerabilities
  in IMAP.");

  script_tag(name:"vuldetect", value:"Sends a crafted IMAP request and checks if the service is
  still responding.");

  script_tag(name:"insight", value:"Two flaws exist in MailEnable Professional Edition 1.52 and
  earlier as well as MailEnable Enterprise Edition 1.01 and earlier:

  A stack-based buffer overflow and an object pointer overwrite.");

  script_tag(name:"impact", value:"A remote attacker can use either vulnerability to execute
  arbitrary code on the target.");

  script_tag(name:"solution", value:"Apply the IMAP hotfix dated 25 November 2004 and found at the
  references.");

  script_xref(name:"URL", value:"http://www.mailenable.com/hotfix/default.asp");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11755");
  script_xref(name:"URL", value:"http://www.hat-squad.com/en/000102.html");

  exit(0);
}

include("host_details.inc");

if (!port = get_app_port(cpe: CPE, service: "imap"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

s = recv_line(socket: soc, length: 1024);
s = chomp(s);
if (!s || "IMAP4rev1 server ready at" >!< s) {
  close(soc);
  exit(0);
}

# Send a long command and see if the service crashes.
#
# nb: this tests only for the stack-based buffer overflow; the object
#     pointer overwrite vulnerability reportedly occurs in the same
#     versions so we just assume it's present if the former is.
c = string("a1 ", crap(8202));

send(socket: soc, data: string(c, "\r\n"));

while(s = recv_line(socket: soc, length: 1024)) {
  s = chomp(s);
  m = eregmatch(pattern: "^a1 (OK|BAD|NO)", string: s, icase: TRUE);
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
    security_message(port:port);
    exit(0);
  }
}

# Logout.
c = string("a2", " LOGOUT");
send(socket: soc, data:string(c, "\r\n"));
while (s = recv_line(socket: soc, length: 1024)) {
  s = chomp(s);
  m = eregmatch(pattern: "^a2 (OK|BAD|NO)", string: s, icase: TRUE);
  if (!isnull(m)) {
    resp = m[1];
    break;
  }
}

close(soc);
exit(99);
