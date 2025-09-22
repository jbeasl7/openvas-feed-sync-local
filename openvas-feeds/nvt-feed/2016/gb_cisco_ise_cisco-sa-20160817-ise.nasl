# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:identity_services_engine";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106193");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-08-19 15:42:28 +0700 (Fri, 19 Aug 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-16 01:29:00 +0000 (Wed, 16 Aug 2017)");

  script_cve_id("CVE-2016-1485");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Identity Services Engine Admin Dashboard Page Cross-Site Scripting Vulnerability (cisco-sa-20160817-ise)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_ise_consolidation.nasl");
  script_mandatory_keys("cisco/ise/detected");

  script_tag(name:"summary", value:"A vulnerability in the web framework code of Cisco Identity
  Services Engine (ISE) could allow an unauthenticated, remote attacker to conduct a cross-site
  scripting (XSS) attack.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient input validation of
  some parameters passed to the web server. An attacker could exploit this vulnerability by
  convincing the user to access a malicious link or by intercepting the user's request and
  injecting malicious code.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to execute arbitrary script
  code in the context of the affected site or allow the attacker to access sensitive browser-based
  information.");

  script_tag(name:"affected", value:"Cisco Identity Services Engine software release 1.3(0.876)
  only.");

  script_tag(name:"solution", value:"See the vendors advisory for solutions.");

  script_xref(name:"URL", value:"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160817-ise");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

patch = get_kb_item("cisco/ise/patch");

if (version_is_equal(version: version, test_version: "1.3.0.876")) {
  if (!patch || version_is_less(version: patch, test_version: "7")) {
    report = report_fixed_ver(installed_version: version, installed_patch: patch,
                              fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
