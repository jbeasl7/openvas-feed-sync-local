# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:fortinet:fortianalyzer";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105200");
  script_version("2024-12-23T07:52:44+0000");
  script_tag(name:"last_modification", value:"2024-12-23 07:52:44 +0000 (Mon, 23 Dec 2024)");
  script_tag(name:"creation_date", value:"2015-02-11 11:16:13 +0100 (Wed, 11 Feb 2015)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2014-2334", "CVE-2014-2335", "CVE-2014-2336");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Fortinet FortiAnalyzer Multiple XSS Vulnerabilities (FG-IR-14-033)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("FortiOS Local Security Checks");
  script_dependencies("gb_fortinet_fortianalyzer_consolidation.nasl");
  script_mandatory_keys("fortinet/fortianalyzer/detected");

  script_tag(name:"summary", value:"Fortinet FortiAnalyzer is prone to multiple cross-site-
  scripting (XSS) vulnerabilities because it fails to properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary
  script code in the browser of an unsuspecting user in the context of the affected site. This can
  allow the attacker to steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"Fortinet FortiAnalyzer prior to version 5.0.7.");

  script_tag(name:"solution", value:"Update to version 5.0.7 or later.");

  script_xref(name:"URL", value:"https://www.fortiguard.com/psirt/FG-IR-14-033");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70887");
  script_xref(name:"Advisory-ID", value:"FG-IR-14-033");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "5.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.7");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
