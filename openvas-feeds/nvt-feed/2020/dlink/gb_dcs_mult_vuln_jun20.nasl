# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# nb: Running against all DCS devices just to be sure as the vendor is known to usually have a wide
# range of affected devices even not actually mentioned as affected.
CPE_PREFIX = "cpe:/o:dlink:dcs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144538");
  script_version("2025-08-07T05:44:51+0000");
  script_tag(name:"last_modification", value:"2025-08-07 05:44:51 +0000 (Thu, 07 Aug 2025)");
  script_tag(name:"creation_date", value:"2020-09-09 06:30:14 +0000 (Wed, 09 Sep 2020)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-11 20:40:00 +0000 (Fri, 11 Sep 2020)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-25078", "CVE-2020-25079");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("D-Link DCS IP Camera Devices Multiple Vulnerabilities (SAP10180) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dcs_consolidation.nasl");
  script_mandatory_keys("d-link/dcs/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Multiple D-Link DCS IP camera devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-25078: Unauthenticated administrator password disclosure via /config/getuser

  - CVE-2020-25079: Authenticated command injection via /cgi-bin/ddns_enc.cgi");

  script_tag(name:"affected", value:"D-Link DCS-2530L and DCS-2670L IP camera devices. Other models
  might be affected as well.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10180");
  script_xref(name:"URL", value:"https://web.archive.org/web/20200617135938/https://twitter.com/Dogonsecurity/status/1273251236167516161");
  script_xref(name:"URL", value:"https://web.archive.org/web/20200617135938/https://twitter.com/Dogonsecurity/status/1271265152118259712");

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

url = "/config/getuser?index=0";

# e.g. (no additional info/strings prepended):
#
# name=admin
# pass=<redacted>
#
# nb:
# - http_vuln_check() is case insensitive by default but we only want to check the response
#   lowercase so an "icase: FALSE" was added
# - As there is no additional data before the above strings we can use "^" as http_vuln_check() is
#   using egrep() internally
if (concl = http_vuln_check(port: port, url: url, pattern: "^pass=.+", check_header: TRUE, extra_check: "^name=.+", icase: FALSE)) {
  report = http_report_vuln_url(port: port, url: url);
  report += '\nResponse:\n\n' + chomp(concl);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
