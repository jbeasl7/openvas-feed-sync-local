# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:fortinet:fortianalyzer";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805640");
  script_version("2024-12-23T07:52:44+0000");
  script_tag(name:"last_modification", value:"2024-12-23 07:52:44 +0000 (Mon, 23 Dec 2024)");
  script_tag(name:"creation_date", value:"2015-06-01 15:56:50 +0530 (Mon, 01 Jun 2015)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2015-3620");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Fortinet FortiAnalyzer Reflected XSS Vulnerability (FG-IR-15-005)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("FortiOS Local Security Checks");
  script_dependencies("gb_fortinet_fortianalyzer_consolidation.nasl");
  script_mandatory_keys("fortinet/fortianalyzer/detected");

  script_tag(name:"summary", value:"Fortinet FortiAnalyzer is prone to a reflected cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the vulnerability in the advanced
  dataset reports page in Fortinet FortiAnalyzer.");

  script_tag(name:"impact", value:"Successful exploitation will allow a context-dependent attacker
  to create a specially crafted request that would execute arbitrary script code in a user's browser
  session within the trust relationship between their browser and the server.");

  script_tag(name:"affected", value:"Fortinet FortiAnalyzer version 5.0.0 through 5.0.10 and 5.2.0
  through 5.2.1.");

  script_tag(name:"solution", value:"Update to version 5.0.11, 5.2.2 or later.");

  script_xref(name:"URL", value:"https://www.fortiguard.com/psirt/FG-IR-15-005");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74646");
  script_xref(name:"URL", value:"http://www.fortinet.com");
  script_xref(name:"Advisory-ID", value:"FG-IR-15-005");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "5.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.11");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.2.0", test_version2: "5.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
