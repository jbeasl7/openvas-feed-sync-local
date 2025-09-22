# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815887");
  script_version("2024-02-15T05:05:40+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2019-17026");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-13 18:15:00 +0000 (Thu, 13 May 2021)");
  script_tag(name:"creation_date", value:"2020-01-09 11:30:32 +0530 (Thu, 09 Jan 2020)");
  script_name("Mozilla Firefox ESR Security Advisories (MFSA2020-03, MFSA2020-03) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to type confusion vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an incorrect alias
  information in IonMonkey JIT compiler for setting array elements.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers
  to execute arbitrary code in the context of the user running the affected
  applications. Failed exploit attempts will likely cause a denial-of-service
  condition.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before
  68.4.1 on Windows.");

  script_tag(name:"solution", value:"Update to Mozilla Firefox ESR version 68.4.1
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-03/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl", "gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"68.4.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"68.4.1", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
