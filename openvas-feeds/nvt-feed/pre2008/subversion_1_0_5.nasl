# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12284");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10519");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2004-0413");
  script_xref(name:"OSVDB", value:"6935");
  script_xref(name:"GLSA", value:"GLSA 200406-07");
  script_xref(name:"SuSE", value:"SUSE-SA:2004:018");
  script_name("Subversion < 1.0.5 SVN Protocol Parser Remote Integer Overflow");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Remote file access");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/subversion", 3690);

  script_tag(name:"summary", value:"A remote overflow exists in Subversion. svnserver fails to
  validate svn:// requests resulting in a heap overflow.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"With a specially crafted request, an attacker can cause arbitrary
  code execution resulting in a loss of integrity.");

  script_tag(name:"solution", value:"Update to version 1.0.5 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");
include("port_service_func.inc");

port = service_get_port(default:3690, proto:"subversion");

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

r = recv_line(socket:soc, length:1024);
if(!r) {
  close(soc);
  exit(0);
}

dat = string("( 2 ( edit-pipeline ) 24:svn://host/svn/VT-Testr0x )");
send(socket:soc, data:dat);
r = recv_line(socket:soc, length:256);
close(soc);
if(!r)
  exit(0);

if(egrep(string:r, pattern:".*subversion-1\.0\.[0-4][^0-9].*")) {
  security_message(port:port);
  exit(0);
}

exit(99);
