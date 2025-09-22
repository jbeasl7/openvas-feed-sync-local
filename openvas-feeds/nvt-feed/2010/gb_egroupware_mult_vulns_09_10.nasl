# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:egroupware:egroupware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100824");
  script_version("2024-07-12T15:38:44+0000");
  script_tag(name:"last_modification", value:"2024-07-12 15:38:44 +0000 (Fri, 12 Jul 2024)");
  script_tag(name:"creation_date", value:"2010-09-24 14:46:08 +0200 (Fri, 24 Sep 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2010-3313", "CVE-2010-3314");

  script_name("EGroupware Multiple Vulnerabilities (Sep 2010) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_egroupware_http_detect.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("egroupware/http/detected");

  script_tag(name:"summary", value:"EGroupware is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Cross-site scripting (XSS) vulnerability in login.php

  - Arbitrary command execution via shell metacharacters");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for
  details.");

  script_xref(name:"URL", value:"http://www.egroupware.org/news?item=93");

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

url = dir + '/login.php?lang="%20style="width:100%;height:100%;display:block;position:absolute;top:0px;left:0px"%20onMouseOver="alert(%27vt-xss-test%27)';

if (http_vuln_check(port: port, url: url, pattern: "onMouseOver=.alert\('vt-xss-test')", check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
