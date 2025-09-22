# SPDX-FileCopyrightText: 2001 SecuriTeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10694");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2001-0767");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("GuildFTPd Directory Traversal");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("FTP");
  script_copyright("Copyright (C) 2001 SecuriTeam");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/guildftpd/detected");

  script_xref(name:"URL", value:"http://www.securiteam.com/windowsntfocus/5CP0S2A4AU.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2789");

  script_tag(name:"solution", value:"Upgrade your FTP server.");

  script_tag(name:"summary", value:"Version 0.97 of GuildFTPd was detected. A security vulnerability in
  this product allows anyone with a valid FTP login to read arbitrary files on the system.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ftp_get_port(default:21);
banner = ftp_get_banner(port:port);
if(!banner)exit(0);

if ("GuildFTPD FTP" >< banner)
{
  if ("Version 0.97" >< banner)
  {
    security_message(port:port);
    exit(0);
  }
  exit(99);
}

exit(0);
