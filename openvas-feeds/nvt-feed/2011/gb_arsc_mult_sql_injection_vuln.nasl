# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902608");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-07-05 13:15:06 +0200 (Tue, 05 Jul 2011)");
  script_cve_id("CVE-2011-2181");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("A Really Simple Chat Multiple SQL Injection Vulnerabilities");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2011/06/02/7");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2011/06/02/1");
  script_xref(name:"URL", value:"http://www.htbridge.ch/advisory/multiple_sql_injections_in_a_really_simple_chat_arsc.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to alter queries to
  the SQL database, execute arbitrary queries to the database, compromise the
  application, access or modify sensitive data.");

  script_tag(name:"affected", value:"A Really Simple Chat version 3.3-rc2.");

  script_tag(name:"insight", value:"The flaws are due to improper validation of user supplied data
  to 'arsc_user parameter' in edit_user.php, 'arsc_layout_id' parameter in
  edit_layout.php and 'arsc_room' parameter in edit_room.php, which allows
  attacker to execute arbitrary SQL commands.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"A Really Simple Chat is prone to multiple SQL injection vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/arsc", "/chat", "/", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item:dir + "/base/index.php", port:port);
  if("Powered by ARSC" >< res && "v3.3-rc2" >< res)
  {
    security_message(port:port);
    exit(0);
  }
}

exit(99);
