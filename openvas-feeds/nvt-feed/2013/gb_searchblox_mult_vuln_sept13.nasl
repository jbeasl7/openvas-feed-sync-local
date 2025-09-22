# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802060");
  script_version("2024-11-19T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-11-19 05:05:41 +0000 (Tue, 19 Nov 2024)");
  script_tag(name:"creation_date", value:"2013-09-03 10:46:51 +0530 (Tue, 03 Sep 2013)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2013-3598", "CVE-2013-3597", "CVE-2013-3590");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SearchBlox Multiple Vulnerabilities (Sep 2013) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"SearchBlox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Input passed via 'name' parameter to 'servlet/CreateTemplateServlet' not properly sanitised
  before being used to create files.

  - Error when accessing 'servlet/CollectionListServlet' servlet when 'action' is set to 'getList'
  can be exploited to disclose usernames and passwords from the database.

  - 'admin/uploadImage.html' script allows to upload an executable file with the image/jpeg content
  type and it can be exploited to execute arbitrary JSP code by uploading a malicious JSP
  script.");

  script_tag(name:"impact", value:"Successful exploitation may allow an attacker to execute
  arbitrary JSP code or obtain potentially sensitive information or can overwrite arbitrary files
  via directory traversal sequences.");

  script_tag(name:"affected", value:"SearchBlox prior to version 7.5 build 1.");

  script_tag(name:"solution", value:"Update to version 7.5 build 1 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54629");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61973");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61974");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61975");
  script_xref(name:"URL", value:"http://www.searchblox.com/developers-2/change-log");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

foreach dir (make_list_unique("/", "/search", "/searchblox", http_cgi_dirs(port: port))) {
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/searchblox/search.html");

  if ('action="servlet/SearchServlet"' >< res && 'id="searchPageCollectionList"' >< res) {
    url = dir + "/searchblox/servlet/CollectionListServlet?action=getList&orderBy=colName&direction=asc";

    if (http_vuln_check(port: port, url: url, check_header: TRUE, pattern: "scanner-auth-password",
                        extra_check: make_list("rootURLStr1", 'scanner-user-agent":"SearchBlox'))) {
      report = http_report_vuln_url(port: port, url: url);
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);
