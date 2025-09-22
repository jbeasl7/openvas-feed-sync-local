# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:unraid:unraid";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143518");
  script_version("2025-01-31T15:39:24+0000");
  script_tag(name:"last_modification", value:"2025-01-31 15:39:24 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2020-02-14 07:25:48 +0000 (Fri, 14 Feb 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-17 17:15:00 +0000 (Fri, 17 Apr 2020)");

  script_cve_id("CVE-2020-5849");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Unraid OS 6.8.0 Web UI Authentication Bypass Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_unraid_consolidation.nasl");
  script_mandatory_keys("unraid/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Unraid OS is prone to an authentication bypass vulnerability in
  the Web UI.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"In order to check if a web page requires authentication, unraid
  uses a auth_request.php file that contains a whitelist which uses the strpos function for
  comparing strings. The whitelist can therefore be bypassed by appending additional characters to
  an entry in the whitelist.");

  script_tag(name:"impact", value:"An unauthenticated attacker might get full control over the
  host.");

  script_tag(name:"affected", value:"Unraid OS version 6.8.0 only.");

  script_tag(name:"solution", value:"Update to version 6.8.1 or later.");

  script_xref(name:"URL", value:"https://sysdream.com/cve-2020-5847-cve-2020-5849-unraid/");
  script_xref(name:"URL", value:"https://forums.unraid.net/topic/87218-unraid-os-version-681-available/");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

# Already no authentication in place
if (get_kb_item("unraid/http/" + port + "/noauth"))
  exit(0);

url = "/webGui/images/green-on.png/Settings";

if (http_vuln_check(port: port, url: url, pattern: '"PanelText">Date and Time',
                    extra_check: '"PanelText">Disk Settings', check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
