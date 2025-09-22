# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805158");
  script_version("2023-12-13T05:05:23+0000");
  script_cve_id("CVE-2014-9560", "CVE-2014-9561");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2015-04-02 13:59:06 +0530 (Thu, 02 Apr 2015)");

  script_tag(name:"qod_type", value:"remote_vul");
  script_name("SoftBB 'post' Parameter Multiple Vulnerabilities");

  script_tag(name:"summary", value:"SoftBB is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able execute sql query or not.");

  script_tag(name:"insight", value:"The flaws are due to the
  /redir_last_post_list.php script not properly sanitizing user-supplied
  input to the 'post' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to execute arbitrary HTML and script code and inject or manipulate
  SQL queries in the back-end database, allowing for the manipulation or
  disclosure of arbitrary data.");

  script_tag(name:"affected", value:"SoftBB version 0.1.3, Prior version may
  also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/129888");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

http_port = http_get_port(default:80);

if(!http_can_host_php(port:http_port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/softbb", "/cms", http_cgi_dirs(port:http_port)))
{

  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"),  port:http_port);

  if ("Copyright SoftBB" >< rcvRes)
  {
    url = dir + "/redir_last_post_list.php?post='SQL-INJECTION-TEST";

    if(http_vuln_check(port:http_port, url:url, check_header:FALSE,
       pattern:"You have an error in your SQL syntax",
       extra_check: "SQL-INJECTION-TEST"))
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);
