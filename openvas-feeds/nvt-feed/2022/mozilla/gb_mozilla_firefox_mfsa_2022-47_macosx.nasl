# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826702");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2022-45403", "CVE-2022-45404", "CVE-2022-45405", "CVE-2022-45406",
                "CVE-2022-45407", "CVE-2022-45408", "CVE-2022-45409", "CVE-2022-45410",
                "CVE-2022-45411", "CVE-2022-40674", "CVE-2022-45415", "CVE-2022-45416",
                "CVE-2022-45417", "CVE-2022-45418", "CVE-2022-45419", "CVE-2022-45420",
                "CVE-2022-45421", "CVE-2022-45412", "CVE-2022-46882", "CVE-2022-46883");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-04 21:07:00 +0000 (Wed, 04 Jan 2023)");
  script_tag(name:"creation_date", value:"2022-11-16 12:34:18 +0530 (Wed, 16 Nov 2022)");
  script_name("Mozilla Firefox Security Advisory (MFSA2022-47) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Symlinks may resolve to partially uninitialized buffers.

  - Service Workers might have learned size of cross-origin media files.

  - Fullscreen notification bypass.

  - Use-after-free in InputStream implementation.

  - Use-after-free of a JavaScript Realm.

  - Loading fonts on workers was not thread-safe.

  - Fullscreen notification bypass via windowName.

  - Use-after-free in Garbage Collection.

  - ServiceWorker-intercepted requests bypassed SameSite cookie policy.

  - Cross-Site Tracing was possible via non-standard override headers.

  - Use-after-free vulnerability in expat.

  - Downloaded file may have been saved with malicious extension.

  - Keystroke Side-Channel Leakage.

  - Service Workers in Private Browsing Mode may have been written to disk.

  - Custom mouse cursor could have been drawn over browser UI.

  - Deleting a security exception did not take effect immediately.

  - Iframe contents could be rendered outside the iframe.

  - Memory safety bugs.

  - Use-after-free in WebGL.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, cause denial of service, disclose sensitive
  information and conduct spoofing on affected system.");

  script_tag(name:"affected", value:"Mozilla Firefox version prior to
  107 on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 107 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-47/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"107")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"107", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
