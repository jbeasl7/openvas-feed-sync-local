# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814895");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2019-9815", "CVE-2019-9816", "CVE-2019-9817", "CVE-2019-9818",
                "CVE-2019-9819", "CVE-2019-9820", "CVE-2019-9821", "CVE-2019-11691",
                "CVE-2019-11692", "CVE-2019-11693", "CVE-2019-11694", "CVE-2019-11695",
                "CVE-2019-11696", "CVE-2019-11697", "CVE-2019-11698", "CVE-2019-11700",
                "CVE-2019-11699", "CVE-2019-11701", "CVE-2019-7317", "CVE-2019-9814",
                "CVE-2019-9800");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-26 16:17:00 +0000 (Fri, 26 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-05-22 12:28:11 +0530 (Wed, 22 May 2019)");
  script_name("Mozilla Firefox Security Advisories (MFSA2019-12, MFSA2019-13) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A type confusion error with object groups and UnboxedObjects.

  - A buffer overflow error in WebGL bufferdata on Linux.

  - A compartment mismatch vulnerability with fetch API.

  - Uninitialized memory leakage vulnerability in Windows sandbox.

  - Incorrect domain name highlighting during page navigation.

  - Memory safety bugs.

  - Multiple use-after-free errors in crash generation server, ChromeEventHandler,
    AssertWorkerThread, XMLHttpRequest and libpng library.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to bypass security restrictions, conduct spoofing
  attacks, read sensitive data and browser history, crash the application and
  execute arbitrary code.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 67 on Windows.");

  script_tag(name:"solution", value:"Update to Mozilla Firefox version 67
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-13/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"67")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"67", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
