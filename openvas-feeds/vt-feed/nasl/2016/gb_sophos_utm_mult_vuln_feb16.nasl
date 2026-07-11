# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sophos:unified_threat_management";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807519");
  script_version("2026-07-10T06:54:17+0000");
  script_tag(name:"last_modification", value:"2026-07-10 06:54:17 +0000 (Fri, 10 Jul 2026)");
  script_tag(name:"creation_date", value:"2016-03-04 18:36:07 +0530 (Fri, 04 Mar 2016)");
  script_tag(name:"cvss_base", value:"5.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-01-19 19:08:44 +0000 (Tue, 19 Jan 2016)");

  script_cve_id("CVE-2015-8000", "CVE-2015-8605", "CVE-2016-0777", "CVE-2016-0778");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Sophos UTM < 9.354 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_sophos_utm_http_detect.nasl");
  script_mandatory_keys("sophos/utm/http/detected");
  script_require_ports("Services/www", 4444);

  script_tag(name:"summary", value:"Sophos UTM is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.

  Note: This script checks for the presence of one of the cross-site scripting (XSS) flaws which
  indicates that the system is also affected by the other included CVEs.");

  script_tag(name:"insight", value:"The following flaws exist / fixes got introduced:

  - Fix [36136]: ISC DHCP security update (CVE-2015-8605)

  - Fix [36201]: Bind Vulnerability (CVE-2015-8000)

  - Fix [36266]: OpenSSH security update (CVE-2016-0777, CVE-2016-0778)

  - Fix [36281]: XSS vulnerability in mod_url_hardening [9.35]

  - Fix [36282]: XSS vulnerability in mod_avscan [9.35]");

  script_tag(name:"affected", value:"Sophos UTM version 9.352-6 and 94988 are known to be affected.
  Other versions can/might be affected as well.");

  script_tag(name:"solution", value:"Update to version 9.354 or later.");

  script_xref(name:"URL", value:"https://community.sophos.com/utm-firewall/f/hardware-installation-up2date-licensing/74825/sophos-utm-9-354-004-released");
  script_xref(name:"URL", value:"https://www.syss.de/fileadmin/dokumente/Publikationen/Advisories/SYSS-2016-009.txt");
  script_xref(name:"URL", value:"https://packetstorm.news/files/id/136019");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121085920/http://www.securityfocus.com/archive/1/537662");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork:TRUE))
  exit(0);

url = "/%3Cscript%3Ealert(document.cookie)%3C/script%3E";

if (http_vuln_check(port: port, url: url, check_header: TRUE, pattern: "<script>alert\(document\.cookie\)</script",
                    extra_check: "<title>Request blocked</title>")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
