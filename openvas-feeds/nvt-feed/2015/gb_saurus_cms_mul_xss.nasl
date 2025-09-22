# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805367");
  script_version("2023-10-27T05:05:28+0000");
  script_cve_id("CVE-2015-1562");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2015-04-13 10:15:43 +0530 (Mon, 13 Apr 2015)");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("Saurus CMS <= 4.7 Multiple XSS Vulnerabilities");

  script_tag(name:"summary", value:"Saurus CMS is prone to multiple cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Multiple errors exist as input passed via:

  - 'search' parameter to the 'user_management.php' script

  - 'data_search' parameter to the 'profile_data.php' script

  - 'filter' parameter to the 'error_log.ph' script

  are not validated before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in the context of an affected site.");

  script_tag(name:"affected", value:"Saurus CMS version 4.7, prior versions may also be affected.");

  script_tag(name:"solution", value:"Update to the Saurus CMS 4.7 release-date:27.01.2015 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Jan/112");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

foreach dir(make_list_unique("/", "/cms", "/sauruscms", http_cgi_dirs(port:port))) {

  if(dir == "/")
    dir = "";

  res = http_get_cache(item:dir + "/admin/", port:port);

  if(">Saurus CMS" >< res) {
    url = dir + '/admin/profile_data.php?data_search=%22%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E%3C!--&profile_search=&profile_id=0';

    if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"alert\(document\.cookie\)")) {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
