# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802442");
  script_version("2023-12-13T05:05:23+0000");
  script_cve_id("CVE-2012-4039");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2012-07-23 12:13:54 +0530 (Mon, 23 Jul 2012)");
  script_name("NetArt Media iBoutique 'key' Parameter SQL Injection Vulnerability");

  script_xref(name:"URL", value:"http://secpod.org/blog/?p=510");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54616");
  script_xref(name:"URL", value:"http://secpod.org/advisories/SecPod_NetArt_Media_iBoutique_SQLi_Vuln.txt");
  script_xref(name:"URL", value:"http://antusanadi.wordpress.com/2012/07/19/netart-media-iboutique-sql-injection-vulnerability/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"Input passed via the 'key' parameter to '/index.php' page is not
  properly verified before being used in a SQL query. This can be exploited to
  manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"NetArt Media iBoutique is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to conduct SQL injection.");

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

foreach dir (make_list_unique("/iboutique", "/", http_cgi_dirs(port:ibPort)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"), port:ibPort);

  if(">Why iBoutique?</" >< rcvRes)
  {
    url = string(dir, "/index.php?mod=products&key=%27");

    if(http_vuln_check(port:ibPort, url:url, pattern:"You have an error" +
                      " in your SQL syntax;", check_header: TRUE))
    {
      security_message(port:ibPort);
      exit(0);
    }
  }
}

exit(99);
