# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832943");
  script_version("2025-01-22T05:38:11+0000");
  script_cve_id("CVE-2024-3852", "CVE-2024-3853", "CVE-2024-3854", "CVE-2024-3855",
                "CVE-2024-3856", "CVE-2024-3857", "CVE-2024-3858", "CVE-2024-3859",
                "CVE-2024-3860", "CVE-2024-3861", "CVE-2024-3862", "CVE-2024-3863",
                "CVE-2024-3302", "CVE-2024-3864", "CVE-2024-3865", "CVE-2024-5702");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-22 05:38:11 +0000 (Wed, 22 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-21 16:52:27 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2024-04-17 22:03:52 +0530 (Wed, 17 Apr 2024)");
  script_name("Mozilla Firefox Security Update (MFSA2024-18) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-3852: GetBoundName in the JIT returned the wrong object

  - CVE-2024-3853: Use-after-free if garbage collection runs during realm initialization

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to run arbitrary code and cause a denial of service.");

  script_tag(name:"affected", value:"Mozilla Firefox version prior to 125 on
  Windows.");

  script_tag(name:"solution", value:"Update to version 125 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-18/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"125")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"125", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
