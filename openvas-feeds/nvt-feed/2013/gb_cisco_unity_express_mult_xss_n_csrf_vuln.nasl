# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803167");
  script_version("2024-05-30T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-05-30 05:05:32 +0000 (Thu, 30 May 2024)");
  script_tag(name:"creation_date", value:"2013-02-06 11:33:49 +0530 (Wed, 06 Feb 2013)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2013-1114", "CVE-2013-1120");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Unity Express Multiple XSS and CSRF Vulnerabilities (Cisco-SA-20130201-CVE-2013-1114, Cisco-SA-20130201-CVE-2013-1120) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("CISCO");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Cisco Unity Express is prone to multiple cross-site scripting
  (XSS) and cross-site request forgery (CSRF) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2013-1114: Multiple cross-site scripting (XSS)

  - CVE-2013-1120: Multiple cross-site request forgery (CSRF)");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary HTML and script code in a users browser session in context of an affected site and
  perform certain actions when a logged-in user visits a specially crafted web page.");

  script_tag(name:"affected", value:"Cisco Unity Express prior to version 8.0.");

  script_tag(name:"solution", value:"Update to version 8.0 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/52045");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57677");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57678");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/24449");
  script_xref(name:"URL", value:"http://infosec42.blogspot.in/2013/02/cisco-unity-express-vulnerabilities.html");
  script_xref(name:"URL", value:"https://www.cisco.com/c/en/us/support/docs/csa/Cisco-SA-20130201-CVE-2013-1114.html");
  script_xref(name:"URL", value:"https://www.cisco.com/c/en/us/support/docs/csa/Cisco-SA-20130201-CVE-2013-1120.html");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

res = http_get_cache(port: port, item: "/Web/SA2/ScriptList.do");
if (res !~ "^HTTP/1\.[01] 200" || res !~ "com\.cisco\.aesop\.(vmgui|gui)")
  exit(0);

url = "/Web/SA2/ScriptList.do?gui_pagenotableData=><script>alert(document.cookie)</script>";

if (http_vuln_check(port: port, url: url, pattern: "><script>alert\(document\.cookie\)</script>",
                    extra_check: make_list("com.cisco.aesop.vmgui", "com.cisco.aesop.gui"),
                    check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
