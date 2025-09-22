# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:identity_services_engine";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106926");
  script_version("2025-07-02T05:41:52+0000");
  script_tag(name:"last_modification", value:"2025-07-02 05:41:52 +0000 (Wed, 02 Jul 2025)");
  script_tag(name:"creation_date", value:"2017-07-06 10:48:11 +0700 (Thu, 06 Jul 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-16 11:32:00 +0000 (Sun, 16 Jul 2017)");

  script_cve_id("CVE-2017-6733");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Identity Services Engine Stored Cross-Site Scripting Vulnerability (cisco-sa-20170705-ise1)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_ise_consolidation.nasl");
  script_mandatory_keys("cisco/ise/detected");

  script_tag(name:"summary", value:"A vulnerability in the web-based application interface of the
  Cisco Identity Services Engine (ISE) portal could allow an unauthenticated, remote attacker to
  conduct a stored cross-site scripting (XSS) attack against a user of the web interface of an
  affected system.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient input validation and
  output-encoding parameters for data that is passed between an affected client and server. An
  attacker could exploit this vulnerability by intercepting targeted user packets and injecting
  malicious code into the targeted traffic stream.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to inject script
  code into the HTTP flow between the targeted user and the affected system.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170705-ise1");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

affected = make_list(
  "2.1.102.101",
  "2.2.0.283",
  "2.3.0.151");

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
