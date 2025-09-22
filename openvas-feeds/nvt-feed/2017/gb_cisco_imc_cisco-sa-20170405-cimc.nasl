# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:integrated_management_controller";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106720");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-04-07 10:17:03 +0200 (Fri, 07 Apr 2017)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-12 01:29:00 +0000 (Wed, 12 Jul 2017)");

  script_cve_id("CVE-2017-6604");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Integrated Management Controller Redirection Vulnerability (cisco-sa-20170405-cimc)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_imc_http_detect.nasl");
  script_mandatory_keys("cisco/imc/detected");

  script_tag(name:"summary", value:"A vulnerability in the web interface of Cisco Integrated
  Management Controller (IMC) Software could allow an unauthenticated, remote attacker to redirect
  a user to a malicious web page.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to improper input validation of
  parameters in HTTP requests. An attacker could exploit this vulnerability by sending a crafted
  HTTP request to an affected system, which could cause the web interface of the affected software
  to redirect the request to a malicious URL.");

  script_tag(name:"impact", value:"This vulnerability is known as an open redirect attack, which is
  used in phishing attacks to get users to visit malicious sites without their knowledge.");

  script_tag(name:"solution", value:"See vendor advisory");

  script_xref(name:"URL", value:"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170405-cimc");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

affected = make_list(
  "2.2(8b)",
  "3.0(1c)",
  "3.1(2c)B");

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
