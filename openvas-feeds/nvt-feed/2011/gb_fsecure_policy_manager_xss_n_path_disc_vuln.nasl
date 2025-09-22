# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:f-secure:policy_manager_web_reporting";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801852");
  script_version("2023-10-27T05:05:28+0000");
  script_cve_id("CVE-2011-1102", "CVE-2011-1103");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2011-03-04 14:32:35 +0100 (Fri, 04 Mar 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("F-Secure Policy Manager 'WebReporting' Module XSS And Path Disclosure Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_fsecure_policy_manager_http_detect.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("fsecure/policy_manager/web_reporting/http/detected");

  script_xref(name:"URL", value:"ftp://ftp.f-secure.com/support/hotfix/fspm/fspm-8.00-windows-hotfix-2.zip");
  script_xref(name:"URL", value:"ftp://ftp.f-secure.com/support/hotfix/fspm/fspm-8.1x-windows-hotfix-3.zip");
  script_xref(name:"URL", value:"ftp://ftp.f-secure.com/support/hotfix/fspm/fspm-9.00-windows-hotfix-4.zip");
  script_xref(name:"URL", value:"ftp://ftp.f-secure.com/support/hotfix/fspm-linux/fspm-8.00-linux-hotfix-2.zip");
  script_xref(name:"URL", value:"ftp://ftp.f-secure.com/support/hotfix/fspm-linux/fspm-8.1x-linux-hotfix-2.zip");
  script_xref(name:"URL", value:"ftp://ftp.f-secure.com/support/hotfix/fspm-linux/fspm-9.00-linux-hotfix-2.zip");
  script_xref(name:"URL", value:"http://secunia.com/advisories/43049");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46547");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1025124");
  script_xref(name:"URL", value:"http://www.f-secure.com/en_EMEA/support/security-advisory/fsc-2011-2.html");

  script_tag(name:"summary", value:"F-Secure Policy Manager is prone to cross-site scripting (XSS)
  and path disclosure vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaws are caused by an error in the 'WebReporting' interface
  when processing user-supplied requests, which could allow cross-site scripting and path disclosure
  attacks.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to disclose
  potentially sensitive information and execute arbitrary code in the context of an application.");

  script_tag(name:"affected", value:"WebReporting Module of F-Secure Policy Manager versions 7.x,
  8.x and 9.x.");

  script_tag(name:"solution", value:"Apply the patch for installed version from the referenced
  links.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

vt_strings = get_vt_strings();

url = dir + "/%3Cscript%3Ealert(%27" + vt_strings["lowercase"] + "%27)%3C/script%3E";
if(http_vuln_check(port:port, url:url, pattern:"<script>alert\('" + vt_strings["lowercase"] + "'\)</script>", check_header:TRUE)) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
