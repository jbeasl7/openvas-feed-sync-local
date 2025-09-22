# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:caucho:resin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901115");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-05-28 16:52:49 +0200 (Fri, 28 May 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2010-2032");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Caucho Resin < 4.0.7 Multiple XSS Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_caucho_resin_http_detect.nasl");
  script_mandatory_keys("caucho/resin/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Caucho Resin is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input
  via the 'digest_username' and 'digest_realm' parameters in resin-admin/digest.php that allows the
  attackers to insert arbitrary HTML and script code.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
  web script or HTML in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Caucho Resin Professional 3.1.5, 3.1.10 and 4.0.6 are known to
  be affected. Other versions might be affected as well.");

  script_tag(name:"solution", value:"Update to version 4.0.7 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/39839");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40251");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/511341");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1005-exploits/cauchoresin312-xss.txt");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

res = http_get_cache(item: "/resin-admin/", port: port);

if (">Resin Admin Login<" >< res) {
  url = '/resin-admin/digest.php?digest_attempt=1&digest_realm="><script>alert' + "('VT-XSS-Test')</script><a&digest_username[]=";
  if (http_vuln_check(port: port, url: url, pattern: "<script>alert\('VT-XSS-Test'\)</script>", check_header: TRUE)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
