# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814944");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2019-9790", "CVE-2019-9791", "CVE-2019-9792", "CVE-2019-9793",
                "CVE-2019-9794", "CVE-2019-9795", "CVE-2019-9796", "CVE-2019-9801",
                "CVE-2018-1850", "CVE-2019-9788");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:39:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-03-26 11:25:40 +0530 (Tue, 26 Mar 2019)");
  script_name("Mozilla Thunderbird Security Advisories (MFSA2019-07, MFSA2019-11) - Windows");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Use-after-free when removing in-use DOM elements,

  - Type inference is incorrect for constructors entered through on-stack replacement with IonMonkey,

  - IonMonkey leaks JS_OPTIMIZED_OUT magic value to script,

  - Improper bounds checks when Spectre mitigations are disabled,

  - Command line arguments not discarded during execution,

  - Type-confusion in IonMonkey JIT compiler,

  - Use-after-free with SMIL animation controller,

  - Cross-origin theft of images with createImageBitmap,

  - Library is loaded from world writable APITRACE_LIB location,

  - Information disclosure via IPC channel messages,

  - Windows programs that are not URL Handlers  are exposed to web content,

  - Chrome process information leak,

  - Upgrade-Insecure-Requests incorrectly enforced for same-origin navigation,

  - Code execution through Copy as cURL in Firefox Developer Tools on macOS,

  - Potential use of uninitialized memory in Prio,

  - Denial of service through successive FTP authorization prompts,

  - Text sent through FTP connection can be incorporated into alert messages,

  - Denial of service through FTP modal alert error messages and

  - WebRTC permissions can display incorrect origin with 'data:' and 'blob:' URLs.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers execute arbitrary code and cause denial of service.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before 60.6 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 60.6 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-11/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"60.6")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"60.6", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
