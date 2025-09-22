# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800286");
  script_version("2024-06-12T05:05:44+0000");
  script_tag(name:"last_modification", value:"2024-06-12 05:05:44 +0000 (Wed, 12 Jun 2024)");
  script_tag(name:"creation_date", value:"2010-02-02 07:26:26 +0100 (Tue, 02 Feb 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2009-4609", "CVE-2009-4610", "CVE-2009-4611", "CVE-2009-4612");

  script_name("Mort Bay Jetty 6.0.0 - 7.0.0 Multiple Vulnerabilities - Active Check");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2009/Oct/319");
  script_xref(name:"URL", value:"http://www.ush.it/team/ush/hack-jetty6x7x/jetty-adv.txt");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_jetty_http_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("jetty/http/detected");

  script_tag(name:"summary", value:"Mort Bay Jetty is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP GET requests and checks the
  responses.");

  script_tag(name:"insight", value:"Inputs passed to the query string to 'jsp/dump.jsp' and to Name
  or Value parameter in 'Session Dump Servlet' is not properly sanitised before being returned to
  the user.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute
  arbitrary HTML and script code in a user's browser session and execute arbitrary commands or
  overwrite files in the context of an affected site.");

  script_tag(name:"affected", value:"Mort Bay Jetty versions 6.0.0 through 7.0.0.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if (!port = get_app_port(cpe :CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork:TRUE))
  exit(0);

xss = "<script>alert(/vt-xss-test/)</script>";
pattern = "<script>alert\(/vt-xss-test/\)</script>";

urls = make_list("/jspsnoop/ERROR/",
                 "/jsp/dump.jsp?",
                 "/test/jsp/dump.jsp?",
                 "/jsp/expr.jsp?A=");

foreach url(urls) {
  url = url + xss;

  if(http_vuln_check(port: port, url: url, pattern: pattern, check_header: TRUE)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

url = "/dump/";

if (http_vuln_check(port: port, url: url, pattern: "<th[^>]+>getPathTranslated:[^<]+</th><td>(/|[A-Z]:\\).*jetty",
                    check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
