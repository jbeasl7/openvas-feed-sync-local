# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805356");
  script_version("2023-12-13T05:05:23+0000");
  script_cve_id("CVE-2015-2780");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-07 20:13:00 +0000 (Tue, 07 Nov 2017)");
  script_tag(name:"creation_date", value:"2015-04-07 12:32:43 +0530 (Tue, 07 Apr 2015)");
  script_name("Berta CMS Arbitrary File Upload Vulnerability");

  script_tag(name:"summary", value:"Berta CMS is prone to a file upload vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to upload file or not.");

  script_tag(name:"insight", value:"The flaw is due to an input passed via
  the 'uploads.php' script is not properly sanitised before being used.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to utilize various admin functionality, execute any
  arbitrary script, and expose potentially sensitive information.");

  script_tag(name:"affected", value:"Berta CMS version before 0.8.10b.");

  script_tag(name:"solution", value:"Upgrade to Berta CMS version 0.8.10b
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"exploit");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Mar/155");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2015/03/30/7");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/131041/Berta-CMS-File-Upload-Bypass.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_xref(name:"URL", value:"http://www.berta.me");
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

foreach dir (make_list_unique("/", "/engine", "/berta/engine", "/berta", http_cgi_dirs(port:http_port)))
{

  if( dir == "/" ) dir = "";
  url = dir + '/login.php';
  rcvRes = http_get_cache(item: url, port:http_port);

  if(rcvRes && "berta v" >< rcvRes && "Log in" >< rcvRes)
  {
    ## Upload file
    url = dir + '/upload.php';

    ## extra check is not possible.
    if(http_vuln_check(port:http_port, url:url, pattern:"O*error"))
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);
