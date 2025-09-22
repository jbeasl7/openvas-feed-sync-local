# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817940");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2021-23969", "CVE-2021-23970", "CVE-2021-23968", "CVE-2021-23974",
                "CVE-2021-23971", "CVE-2021-23978", "CVE-2021-23979", "CVE-2021-23973",
                "CVE-2021-23972", "CVE-2021-23975");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-01 02:15:00 +0000 (Sat, 01 May 2021)");
  script_tag(name:"creation_date", value:"2021-02-24 12:39:22 +0530 (Wed, 24 Feb 2021)");
  script_name("Mozilla Firefox Security Advisories (MFSA2021-07, MFSA2021-09) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Content Security Policy violation report could have contained the
    destination of a redirect.

  - Multithreaded WASM triggered assertions validating separation of script domains.

  - noscript elements could have led to an HTML Sanitizer bypass.

  - A website's Referrer-Policy could have been be overridden, potentially
    resulting in the full URL being sent as a Referrer.

  - HTTP Auth phishing warning was omitted when a redirect is cached.

  - 'about:memory' Measure function caused an incorrect pointer operation.

  - MediaError message property could have leaked information about cross-origin resources.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to run arbitrary code, cause denial of service, bypass security restrictions
  and disclose sensitive information.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 86 on
  Windows.");

  script_tag(name:"solution", value:"Update to Mozilla Firefox version 86
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-07/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl", "gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"86")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"86", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
