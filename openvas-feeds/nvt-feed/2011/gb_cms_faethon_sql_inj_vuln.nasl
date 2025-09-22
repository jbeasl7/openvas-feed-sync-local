# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802162");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2011-09-16 17:22:17 +0200 (Fri, 16 Sep 2011)");
  script_cve_id("CVE-2009-5094");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CMS Faethon 'info.php' SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/30098");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33775");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/48758");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/8054/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to manipulate SQL
  queries by injecting arbitrary SQL code.");

  script_tag(name:"affected", value:"CMS Faethon version 2.2 Ultimate.");

  script_tag(name:"insight", value:"The flaw is due to input passed to the 'item' parameter in
  'info.php' is not properly sanitised before being used in SQL queries.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"CMS Faethon is prone to an SQL injection (SQLi) vulnerability.");

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

foreach dir(make_list_unique("/faethon", "/22_ultimate", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/index.php", port:port);

  if('>Powered by <' >< res && '>CMS Faethon' >< res)
  {
    url = dir + "/info.php?item='";
    if(http_vuln_check(port:port, url:url, pattern:'You have an error in' +
                                  ' your SQL syntax;'))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
