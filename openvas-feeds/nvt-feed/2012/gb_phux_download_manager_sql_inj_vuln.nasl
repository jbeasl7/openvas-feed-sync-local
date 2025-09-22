# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802586");
  script_version("2023-12-13T05:05:23+0000");
  script_cve_id("CVE-2012-0980");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2012-02-07 12:53:59 +0530 (Tue, 07 Feb 2012)");
  script_name("phux Download Manager 'file' Parameter SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18432/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51725");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to cause SQL injection
  attack and gain sensitive information.");

  script_tag(name:"affected", value:"phux Download Manager version 0.1 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an improper validation of user-supplied
  input via the 'file' parameter to download.php, which allows attacker to
  manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"phux Download Manager is prone to an SQL injection (SQLi) vulnerability.");

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

foreach dir (make_list_unique("/", "/download_manager", "/phux", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item: dir + "/index.php", port:port);

  if(!isnull(rcvRes) && ">phux.org's<" >< rcvRes &&
                        "Public Download Center<" >< rcvRes)
  {
    url = dir + "/download.php?file='";

    if(http_vuln_check(port:port, url:url, pattern:"mysql_num_rows\(\): " +
                          "supplied argument is not a valid MySQL"))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
