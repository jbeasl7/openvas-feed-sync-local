# SPDX-FileCopyrightText: 2004 Noam Rathaus
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11978");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1783");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9350");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Flash FTP Server Directory Traversal Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("FTP");
  script_copyright("Copyright (C) 2004 Noam Rathaus");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/flash/ftp/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to the latest version of this software.");

  script_tag(name:"summary", value:"Flash FTP Server easy-to-set-up FTP server for all Windows platforms.

  Some bugs were found that will allow a malicious user to write and read anywhere on the disk.");

  script_tag(name:"affected", value:"Flash Ftp server 1.0 is known to be affected.");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ftp_get_port(default:21);
banner = ftp_get_banner(port:port);
if ( ! banner ) exit(0);

if(egrep(pattern:"^220 Flash FTP Server v(1\.|2\.[01]) ready", string:banner))
  security_message(port);
