# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:opmantek:open-audit";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100654");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2010-05-25 18:01:00 +0200 (Tue, 25 May 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Open-Audit 20081013/20091223-RC Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40315");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_open_audit_detect.nasl");
  script_mandatory_keys("open-audit/detected");

  script_tag(name:"summary", value:"Open-Audit is prone to multiple vulnerabilities, including a
  local fileinclude (LFI) vulnerability and multiple SQL injection (SQLi), cross-site scripting
  (XSS), and authentication bypass vulnerabilities.");

  script_tag(name:"impact", value:"An attacker can exploit these vulnerabilities to steal cookie-based
  authentication credentials, compromise the application, access or modify data, exploit latent vulnerabilities
  in the underlying database, bypass security restrictions, obtain potentially sensitive information,
  perform unauthorized actions, or execute arbitrary local scripts in the context of the webserver process,
  other attacks are also possible.");

  script_tag(name:"affected", value:"Open-Audit 20081013 and 20091223-RC are vulnerable, other versions may
  also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

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

url = dir + "/list.php?view=%3Cscript%3Ealert(%27XSS-Test%27)%3B%3C%2Fscript%3E";

if (http_vuln_check(port:port, url:url,pattern:"<script>alert\('XSS-Test'\);</script>", check_header:TRUE)) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit(0);
}

exit(0);
