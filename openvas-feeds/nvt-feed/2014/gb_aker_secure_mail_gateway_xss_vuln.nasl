# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804413");
  script_version("2025-09-22T07:08:28+0000");
  script_tag(name:"last_modification", value:"2025-09-22 07:08:28 +0000 (Mon, 22 Sep 2025)");
  script_tag(name:"creation_date", value:"2014-03-17 13:12:47 +0530 (Mon, 17 Mar 2014)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2013-6037");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Aker Secure Mail Gateway <= 2.5.2 XSS Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Aker Secure Mail Gateway is prone to a cross-site scripting
  (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Input passed via the 'msg_id' GET parameter to
  webgui/cf/index.php is not properly sanitised before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute
  arbitrary HTML and script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"Aker Secure Mail Gateway version 2.5.2 and prior.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57236");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66024");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/687278");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125599");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Mar/51");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

res = http_get_cache(port: port, item: "/login");

if (">Aker Secure Mail Gateway<" >!< res || "Aker Security Solutions<" >!< res)
  exit(0);

url = "/webgui/cf/index.php?msg_id=><script>alert(document.cookie);</script>";

if (http_vuln_check(port: port, url: url, check_header: TRUE,
                    pattern:"><script>alert\(document\.cookie\);</script>",
                    extra_check: ">Aker Secure Mail Gateway")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
