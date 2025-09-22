# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813816");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2018-12359", "CVE-2018-12360", "CVE-2018-12361", "CVE-2018-12362",
                "CVE-2018-12363", "CVE-2018-12364", "CVE-2018-12365", "CVE-2018-5156",
                "CVE-2018-12371", "CVE-2018-12366", "CVE-2018-12367", "CVE-2018-5187",
                "CVE-2018-5188");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-06 18:39:00 +0000 (Thu, 06 Dec 2018)");
  script_tag(name:"creation_date", value:"2018-08-07 11:07:09 +0530 (Tue, 07 Aug 2018)");
  script_name("Mozilla Thunderbird Security Advisories (MFSA2018-19, MFSA2018-19) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Memory safety bugs.

  - Timing attack related to PerformanceNavigationTiming.

  - An invalid data handling during QCMS transformations.

  - An integer overflow vulnerability in the Skia library during edge
    builder allocation.

  - A compromised IPC child process can list local filenames.

  - NPAPI plugins, such as Adobe Flash, can send non-simple cross-origin
    requests, bypassing CORS.

  - An use-after-free error when appending DOM nodes.

  - A vulnerability can occur when capturing a media stream when the media
    source type is changed as the capture is occurring.

  - An integer overflow error in SSSE3 scaler.

  - An integer overflow error can occur in the SwizzleData code while calculating
    buffer sizes.

  - An use-after-free error when using focus().

  - A buffer overflow error using computed size of canvas element.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause denial of service condition, conduct csrf and timing attacks,
  access private local files and execute arbitrary code.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before 60 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 60 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-19/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Thunderbird/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"60")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"60", install_path:path);
  security_message(data:report);
  exit(0);
}
