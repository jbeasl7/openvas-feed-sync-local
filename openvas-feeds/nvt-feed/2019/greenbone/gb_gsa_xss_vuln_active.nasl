# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:greenbone:greenbone_security_assistant";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108640");
  script_version("2024-06-12T05:05:44+0000");
  script_tag(name:"last_modification", value:"2024-06-12 05:05:44 +0000 (Wed, 12 Jun 2024)");
  script_tag(name:"creation_date", value:"2019-09-10 07:01:39 +0000 (Tue, 10 Sep 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-22 18:18:00 +0000 (Tue, 22 Jun 2021)");

  script_cve_id("CVE-2019-25047");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Greenbone Security Assistant (GSA) 8.0 < 8.0.2 XSS Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_greenbone_gsa_http_detect.nasl", "gb_greenbone_os_consolidation.nasl");
  script_mandatory_keys("greenbone/gsa/80plus/http/detected");
  script_exclude_keys("greenbone/gos/detected");

  script_tag(name:"summary", value:"Greenbone Security Assistant (GSA) is prone to a reflected
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"affected", value:"Greenbone Security Assistant (GSA) 8.0 up to and including
  version 8.0.1.");

  script_tag(name:"solution", value:"Update to Greenbone Security Assistant (GSA) 8.0.2 or later.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_xref(name:"URL", value:"https://github.com/greenbone/gsa/issues/1601");
  script_xref(name:"URL", value:"https://github.com/greenbone/gsa/pull/1603");

  exit(0);
}

if (get_kb_item("greenbone/gos/detected")) # Covered by 2019/greenbone/gb_gos_xss_vuln_active.nasl
  exit(0);

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

vt_strings = get_vt_strings();
pattern = vt_strings["lowercase_rand"];

url = "/%0a%0a%3Cscript%3Ealert('" + pattern + "');%3C/script%3Etest";

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);
if (!res)
  exit(0);

check = '<p>The requested URL /\n\n<script>alert(\'' + pattern + '\');</script>test is not available</p>';

if (res =~ "HTTP/1\.[01] 404" && check >< res) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
