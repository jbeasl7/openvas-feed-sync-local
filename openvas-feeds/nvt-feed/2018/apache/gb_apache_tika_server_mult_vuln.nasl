# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tika";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113167");
  script_version("2025-08-22T05:39:46+0000");
  script_tag(name:"last_modification", value:"2025-08-22 05:39:46 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"creation_date", value:"2018-04-26 11:12:13 +0200 (Thu, 26 Apr 2018)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2018-1335", "CVE-2018-1338", "CVE-2018-1339");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tika <= 1.17 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_tika_http_detect.nasl");
  script_mandatory_keys("apache/tika/detected");

  script_tag(name:"summary", value:"Apache Tika is prone to multiple vulnerabilities, including
  command execution and denial of service (DoS).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - In Apache Tika, clients could send carefully crafted headers to tika-server that could be used
  to inject commands into the command line of the server running tika-server. This vulnerability
  only affects those running tika-server on a server that is open to untrusted clients.

  - A carefully crafted (or fuzzed) file can trigger an infinite loop in Apache Tika's BPGParser.

  - A carefully crafted (or fuzzed) file can trigger an infinite loop in Apache Tika's
  ChmParser.");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to eventually
  gain full control over the target system.");

  script_tag(name:"affected", value:"Apache Tika version 1.17 and prior.");

  script_tag(name:"solution", value:"Update to version 1.18 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/b3ed4432380af767effd4c6f27665cc7b2686acccbefeb9f55851dca@%3Cdev.tika.apache.org%3E");
  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/4d20c5748fb9f836653bc78a1bad991ba8485d82a1e821f70b641932@%3Cdev.tika.apache.org%3E");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.18")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.18");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
