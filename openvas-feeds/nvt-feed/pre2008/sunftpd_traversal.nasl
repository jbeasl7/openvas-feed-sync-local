# SPDX-FileCopyrightText: 2003 Xue Yong Zhi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11374");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_cve_id("CVE-2001-0283");
  script_name("SunFTP directory traversal");
  script_category(ACT_MIXED_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_family("FTP");
  script_copyright("Copyright (C) 2003 Xue Yong Zhi");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "logins.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/sunftp/detected");

  script_tag(name:"summary", value:"Directory traversal vulnerability in SunFTP build 9 allows
  remote attackers to read arbitrary files via .. (dot dot) characters in various commands,
  including (1) GET, (2) MKDIR, (3) RMDIR, (4) RENAME, or (5) PUT.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ftp_get_port(default:21);
banner = ftp_get_banner(port: port);
if(!banner || "SunFTP " >!< banner )
  exit(0);

if(safe_checks())
{
  if("SunFTP b9"><banner) {
    security_message(port:port);
  }
  exit(0);
}

kb_creds = ftp_get_kb_creds();
login = kb_creds["login"];
pass = kb_creds["pass"];
if(!login)exit(0);

soc = open_sock_tcp(port);
if(soc)
{
  if(ftp_authenticate(socket:soc, user:login, pass:pass))
  {
    #dir name may already exists, try 5 times to get one unused
    for(i=0;i<5;i++) {
      dir=crap(i+10);
      mkdir=string("MKD ../", dir, "\r\n");
      cwd=string("CWD ", dir, "\r\n");
      rmd=string("RMD ../", dir, "\r\n");
      up=string("CWD ..\r\n");

      send(socket:soc, data:mkdir);
      b = ftp_recv_line(socket:soc);
      if(egrep(pattern:"^257 .*", string:b)) {

        #If the system is not vulnerable, it may create the
        #new dir in the current dir, instead of the parent dir.
        #if we can CWD into it, the system is not vulnerable.

        send(socket:soc, data:cwd);
        b = ftp_recv_line(socket:soc);
        if(!egrep(pattern:"^250 .*", string:b)) {
          security_message(port);
        } else {
          send(socket:soc, data:up); #cd..
        }
        send(socket:soc, data:rmd);
        break;
      }
    }
    ftp_close(socket:soc);
    exit(0);
  }
  close(soc);
}
