# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sap:netweaver_application_server_java";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106104");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"creation_date", value:"2016-06-21 15:14:09 +0700 (Tue, 21 Jun 2016)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-20 19:01:00 +0000 (Tue, 20 Apr 2021)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2016-3974", "CVE-2016-3975", "CVE-2016-3976");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SAP NetWeaver AS Java Multiple Vulnerabilities (2235994, 2234971, 2238375)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_sap_netweaver_as_java_http_detect.nasl");
  script_mandatory_keys("sap/netweaver/as_java/detected");

  script_tag(name:"summary", value:"SAP NetWeaver Application Server (AS) Java is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"SAP NetWeaver AS Java contains multiple vulnerabilities:

  - CVE-2016-3974: An XML external entity (XXE) vulnerability in the Configuration Wizard allows
  remote attackers to cause a denial of service, conduct SMB Relay attacks, or access arbitrary
  files via a crafted XML request related to the ctcprotocol servlet.

  - CVE-2016-3975: Anonymous attacker can use an XSS vulnerability to hijack session data of
  administrators or users of a web resource.

  - CVE-2016-3976: An authorized attacker can use a directory traversal attack to read files from
  the server and then escalate his or her privileges.

  On April 6 2021, Onapsis and SAP released a new threat intelligence report to help SAP customers
  protect from active cyber threats seeking to specifically target, identify and compromise
  organizations running unprotected SAP applications, through a variety of cyberattack vectors. This
  VT is covering one or more vulnerabilities mentioned in that report.");

  script_tag(name:"impact", value:"A remote attacker may cause a denial of service, access arbitrary
  files or hijack user sessions. An authenticated remote attacker may read arbitrary files leading
  to privilege escalation.");

  script_tag(name:"affected", value:"SAP NetWeaver AS Java version 7.10 (7.1) through 7.50 (7.5).");

  script_tag(name:"solution", value:"See the referenced vendor advisories for a solution.");

  script_xref(name:"URL", value:"https://launchpad.support.sap.com/#/notes/2235994");
  script_xref(name:"URL", value:"https://launchpad.support.sap.com/#/notes/2234971");
  script_xref(name:"URL", value:"https://launchpad.support.sap.com/#/notes/2238375");
  script_xref(name:"URL", value:"https://onapsis.com/active-cyberattacks-mission-critical-sap-applications");
  script_xref(name:"URL", value:"https://us-cert.cisa.gov/ncas/current-activity/2021/04/06/malicious-cyber-activity-targeting-critical-sap-applications");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "7.10", test_version2: "7.50")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
