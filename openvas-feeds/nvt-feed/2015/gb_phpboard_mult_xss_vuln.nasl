# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805352");
  script_version("2023-12-13T05:05:23+0000");
  script_cve_id("CVE-2015-2217");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2015-03-14 13:06:08 +0530 (Sat, 14 Mar 2015)");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("PHP Board <= 2.2.7 Multiple XSS Vulnerabilities");

  script_tag(name:"summary", value:"PHP Board is prone to multiple cross-site scripting
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaws are due to the 'q' parameter in the search.php script
  and the 'avatar' parameter in the profile.php script are validated before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in the context of an affected site.");

  script_tag(name:"affected", value:"PHP Board version 2.2.7.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/130684/Ultimate-PHP-Board-UPB-2.2.7-Cross-Site-Scripting.html");
  script_xref(name:"URL", value:"https://github.com/PHP-Outburst/myUPB/pull/27");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

if(!http_can_host_php(port:port))
  exit(0);

foreach dir(make_list_unique("/", "/upb", "/chat/upb", http_cgi_dirs(port:port))) {

  if(dir == "/")
    dir = "";

  res = http_get_cache(item:dir + "/", port:port);

  if(res && res =~ "Powered by.*UPB") {
    url = dir + "/search.php?q='><script>alert(document.cookie)</script>";

    if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"<script>alert\(document\.cookie\)</script>")) {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
