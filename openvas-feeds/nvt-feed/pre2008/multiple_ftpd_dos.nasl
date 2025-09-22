# SPDX-FileCopyrightText: 2000 StrongHoldNET
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10822");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_name("Multiple WarFTPd DoS");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("FTP");
  script_copyright("Copyright (C) 2000 StrongHoldNET");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/war_ftpd/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2698");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to the latest version of WarFTPd.");

  script_tag(name:"summary", value:"The remote WarFTPd server is running a 1.71 version.");

  script_tag(name:"impact", value:"It is possible for a remote user to cause a denial of
  service on a host running Serv-U FTP Server, G6 FTP Server or WarFTPd Server. Repeatedly
  submitting an 'a:/' GET or RETR request, appended with arbitrary data, will cause the CPU
  usage to spike to 100%.");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ftp_get_port(default:21);
banner = ftp_get_banner(port: port);
if( banner && "WarFTPd 1.71" >< banner) {
  security_message(port:port);
  exit(0);
}

exit(99);
