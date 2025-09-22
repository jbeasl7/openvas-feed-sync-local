# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# nb: Running against all DSL devices just to be sure as the vendor is known to usually have a wide
# range of affected devices even not actually mentioned as affected.
CPE_PREFIX = "cpe:/o:dlink:dsl";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103706");
  script_version("2025-06-26T05:40:52+0000");
  script_tag(name:"last_modification", value:"2025-06-26 05:40:52 +0000 (Thu, 26 Jun 2025)");
  script_tag(name:"creation_date", value:"2013-05-06 12:58:41 +0200 (Mon, 06 May 2013)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("D-Link DSL-320B Multiple Security Vulnerabilities (May 2013) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dsl_consolidation.nasl");
  script_mandatory_keys("d-link/dsl/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"D-Link DSL-320B devices are prone multiple security
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Access to the config file without authentication

  - Access to the logfile without authentication

  - Stored cross-site scripting (XSS) within parental control");

  script_tag(name:"impact", value:"An attacker can exploit these issues to gain access to
  potentially sensitive information, decrypt stored passwords, steal cookie-based authentication
  credentials.");

  script_tag(name:"affected", value:"D-Link DSL-320B devices with firmware versions 1.23 and prior.
  Other models might be affected as well.");

  script_tag(name:"solution", value:"- D-Link DSL-320B devices: A firmware update is available.
  Please see the references for more information.

  - Other models: Please contact the vendor for more information");

  script_xref(name:"URL", value:"https://web.archive.org/web/20221203162240/http://www.s3cur1ty.de/m1adv2013-018");
  script_xref(name:"URL", value:"https://www.dlink.com/uk/en/products/dsl-320b-adsl-2-ethernet-modem");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www"))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

if (!get_app_location(cpe: cpe, port: port, nofork: TRUE))
  exit(0);

url = "/config.bin";

# e.g.:
# <sysUserName value="admin"/>
# <sysPassword value="dGVzdA=="/>
#
# nb: http_vuln_check() is case insensitive by default. This should be fine for our purpose as the
# used pattern below are strict enough. Also no "^" required for now due to the same reason but
# could be added if we ever see false positives here.
if (http_vuln_check(port: port, url: url, pattern: "<sysPassword value=", extra_check: "<sysUserName value=")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
