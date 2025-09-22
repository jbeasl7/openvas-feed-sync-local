# SPDX-FileCopyrightText: 2003 Digital Defense Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11207");
  script_version("2023-07-07T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-07-07 05:05:26 +0000 (Fri, 07 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10078");
  script_cve_id("CVE-1999-0256");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("War FTP Daemon USER/PASS Overflow");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2003 Digital Defense Inc.");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/war_ftpd/detected");

  script_tag(name:"solution", value:"Upgrade to the latest release of the War FTP Daemon
  available from the referenced link.");

  script_tag(name:"summary", value:"The version of War FTP Daemon running on this host contains
  a buffer overflow in the code that handles the USER and PASS commands.");

  script_tag(name:"impact", value:"A potential intruder could use this vulnerability to crash the
  server, as well as run arbitrary commands on the system.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ftp_get_port(default:21);
r = ftp_get_banner(port:port);
if(!r) exit(0);

if(egrep(pattern:"WAR-FTPD 1.([0-5][0-9]|6[0-5])[^0-9]*Ready", string:r, icase:TRUE)) {
  security_message(port:port);
}
