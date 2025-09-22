# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826789");
  script_version("2025-09-16T05:38:45+0000");
  script_cve_id("CVE-2023-23597", "CVE-2023-23598", "CVE-2023-23599", "CVE-2023-23601",
                "CVE-2023-23602", "CVE-2023-23603", "CVE-2023-23604", "CVE-2023-23605",
                "CVE-2023-23606");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-08 13:51:00 +0000 (Thu, 08 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-01-18 13:22:42 +0530 (Wed, 18 Jan 2023)");
  script_name("Mozilla Firefox Security Advisories (MFSA2022-54, MFSA2023-02) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Logic bug in process allocation allowed to read arbitrary files.

  - Malicious command could be hidden in devtools output on Windows.

  - URL being dragged from cross-origin iframe into same tab triggers navigation.

  - Content Security Policy wasn't being correctly applied to WebSockets in WebWorkers.

  - Calls to <code>console.log</code> allowed bypassing Content Security Policy via
    format directive.

  - Creation of duplicate <code>SystemPrincipal</code> from less secure contexts.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to execute arbitrary code, cause denial of service, disclose
  sensitive information and conduct spoofing attack.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  109 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 109
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-01/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"109")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"109", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
