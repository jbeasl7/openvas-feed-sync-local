# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804784");
  script_version("2023-10-27T05:05:28+0000");
  script_cve_id("CVE-2014-8381");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2014-10-28 12:24:56 +0530 (Tue, 28 Oct 2014)");
  script_name("Megapolis.Portal Manager Multiple Cross Site Scripting Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/97649");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70615");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/128725");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Oct/77");

  script_tag(name:"summary", value:"Megapolis.Portal Manager is prone to multiple cross-site
  scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to /control/uk/publish/category script which
  does not validate input to the 'dateFrom' and 'dateTo' parameters before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in the context of an affected site.");

  script_tag(name:"affected", value:"Megapolis.Portal Manager.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);

foreach dir (make_list_unique("/", "/portal", "/manager", http_cgi_dirs(port:port))) {

  if(dir == "/")
    dir = "";

  res = http_get_cache(item:dir + "/control/uk/publish/category",  port:port);

  if("dateFrom" >< res && "dateTo" >< res && "control/uk/publish/category" >< res) {

    url = dir + '/control/uk/publish/category?dateFrom="><script>alert(document.cookie)</script>';

    if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"<script>alert\(document.cookie\)</script>", extra_check:make_list("dateFrom", "dateTo"))) {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
