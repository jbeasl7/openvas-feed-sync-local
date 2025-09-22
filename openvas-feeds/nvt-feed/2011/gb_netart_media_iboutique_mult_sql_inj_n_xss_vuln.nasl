# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802404");
  script_version("2023-12-13T05:05:23+0000");
  script_cve_id("CVE-2010-5020");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2011-11-14 13:46:57 +0530 (Mon, 14 Nov 2011)");
  script_name("NetArt Media iBoutique 'page' SQL Injection and XSS Vulnerabilities");
  script_xref(name:"URL", value:"http://milw0rm.com/exploits/6444");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41014");
  script_xref(name:"URL", value:"http://secunia.com/advisories/31871");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/13945/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"NetArt Media iBoutique is prone to multiple SQL injection and cross-site scripting vulnerabilities.");

  script_tag(name:"insight", value:"Multiple flaws are due to an:

  - Input passed to the 'cat' and 'key'  parameter in index.php (when 'mod'
  is set to 'products') is not properly sanitised before being used in a SQL query.

  - Input passed to the 'page' parameter in index.php is not properly sanitised
  before being used in a SQL query.

  This can further be exploited to conduct cross-site scripting attacks
  via SQL error messages.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to conduct SQL
  injection and cross-site scripting attacks.");

  script_tag(name:"affected", value:"NetArt Media iBoutique version 4.0");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

ibPort = http_get_port(default:80);

if(!http_can_host_php(port:ibPort)){
  exit(0);
}

foreach dir (make_list_unique("/iboutique", http_cgi_dirs(port:ibPort)))
{

  if(dir == "/") dir = "";

  ##Request to confirm application
  rcvRes = http_get_cache(item: dir + "/index.php", port:ibPort);

  if(">Why iBoutique?</" >< rcvRes)
  {
    url = string(dir, "/index.php?page='");

    if(http_vuln_check(port:ibPort, url:url, pattern:"You have an error" +
                      " in your SQL syntax;", check_header: TRUE))
    {
      security_message(port:ibPort);
      exit(0);
    }
  }
}

exit(99);
