# SPDX-FileCopyrightText: 2003 Digital Defense Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11205");
  script_version("2023-07-07T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-07-07 05:05:26 +0000 (Fri, 07 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/966");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2000-0131");
  script_name("War FTP Daemon CWD/MKD Buffer Overflow");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2003 Digital Defense Inc.");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/war_ftpd/detected");

  script_tag(name:"solution", value:"Visit the referenced link and download the latest version of WarFTPd.");

  script_tag(name:"summary", value:"The version of the War FTP Daemon running on this host is vulnerable to a
  buffer overflow attack. This is due to improper bounds checking within the code that handles both the CWD
  and MKD commands.");

  script_tag(name:"impact", value:"By exploiting this vulnerability, it is possible to crash the server, and
  potentially run arbitrary commands on this system.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ftp_get_port(default:21);
r = ftp_get_banner(port:port);
if(!r)exit(0);

if("WAR-FTPD 1.66x4" >< r || "WAR-FTPD 1.67-03" >< r) {
  security_message(port:port);
}

exit(0);
