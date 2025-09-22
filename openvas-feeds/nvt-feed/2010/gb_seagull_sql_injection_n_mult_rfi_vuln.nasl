# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801513");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2010-09-10 16:37:50 +0200 (Fri, 10 Sep 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-3209", "CVE-2010-3212");
  script_name("Seagull SQL Injection and Multiple Remote File Inclusion Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41169");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14838/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1008-exploits/seagull-rfi.txt");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1008-exploits/seagull-sql.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error in the 'Config/Container.php', which is not properly validating the
  input passed to 'includeFile' parameter.

  - An error in the 'fog/lib/pear/HTML/QuickForm.php', which is not properly
  validating the input passed to 'includeFile' parameter.

  - An error in the 'fog/lib/pear/DB/NestedSet.php', which is not properly
  validating the input passed to 'driverpath' parameter.

  - An error in the 'fog/lib/pear/DB/NestedSet/Output.php', which is not properly
  validating the input passed to 'path' parameter.

  - An SQL injection error in 'index.php', which allows remote attackers to
  execute arbitrary SQL commands via the frmQuestion parameter in a retrieve
  action, in conjunction with a user/password PATH_INFO.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Seagull is prone to SQL injection and multiple remote file inclusion vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  code on the vulnerable Web server and to execute arbitrary SQL commands.");

  script_tag(name:"affected", value:"Seagull version 0.6.7");

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

foreach dir (make_list_unique("/seagull/www", "/Seagull", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item:string(dir , "/index.php"), port:port);

  if("<title>Seagull Framework :: Home<" >< res)
  {
    req = http_get(item:string(dir, "/index.php/user/password/?action=" +
                                 "retrieve&frmEmail=111-222-1933email@add" +
                                 "ress.tst&frmQuestion=1'[SQLI]&frmAnswer" +
                                 "=111-222-1933email@address.tst&submitte" +
                                  "d=retrieve"),  port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    if('this->whereAdd' >< res && 'Object of class DB_' >< res)
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
