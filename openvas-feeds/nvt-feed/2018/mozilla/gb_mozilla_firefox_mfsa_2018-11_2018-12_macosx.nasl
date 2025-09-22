# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813358");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2018-5154", "CVE-2018-5155", "CVE-2018-5157", "CVE-2018-5158",
                "CVE-2018-5159", "CVE-2018-5160", "CVE-2018-5152", "CVE-2018-5153",
                "CVE-2018-5163", "CVE-2018-5164", "CVE-2018-5166", "CVE-2018-5167",
                "CVE-2018-5168", "CVE-2018-5169", "CVE-2018-5172", "CVE-2018-5173",
                "CVE-2018-5174", "CVE-2018-5175", "CVE-2018-5176", "CVE-2018-5177",
                "CVE-2018-5180", "CVE-2018-5181", "CVE-2018-5182", "CVE-2018-5151",
                "CVE-2018-5150", "CVE-2018-5165");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-03 18:33:00 +0000 (Fri, 03 Aug 2018)");
  script_tag(name:"creation_date", value:"2018-05-11 11:54:25 +0530 (Fri, 11 May 2018)");
  script_name("Mozilla Firefox Security Advisories (MFSA2018-11, MFSA2018-12) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Use-after-free error with SVG animations and clip paths.

  - Use-after-free error with SVG animations and text paths.

  - Same-origin bypass of PDF Viewer to view protected PDF files.

  - Malicious PDF can inject JavaScript into PDF Viewer.

  - Integer overflow and out-of-bounds write errors in Skia.

  - Uninitialized memory use by WebRTC encoder.

  - WebExtensions information leak error through webRequest API.

  - Out-of-bounds read error in mixed content websocket messages.

  - Replacing cached data in JavaScript Start-up Bytecode Cache.

  - CSP not applied to all multipart content sent with multipart/x-mixed-replace.

  - WebExtension host permission bypass error through filterReponseData.

  - Improper linkification of chrome: and javascript: content in web console and JavaScript debugger.

  - Lightweight themes can be installed without user interaction.

  - Dragging and dropping link text onto home button can set home page to include chrome pages.

  - Pasted script from clipboard can run in the Live Bookmarks page or PDF viewer.

  - File name spoofing of Downloads panel with Unicode characters.

  - Windows Defender SmartScreen UI runs with less secure behavior for downloaded files in Windows 10 April 2018 Update.

  - Universal CSP bypass error on sites using strict-dynamic in their policies.

  - JSON Viewer script injection.

  - Buffer overflow error in XSLT during number formatting.

  - Checkbox for enabling Flash protected mode is inverted in 32-bit Firefox.

  - Heap-use-after-free error in mozilla::WebGLContext::DrawElementsInstanced.

  - Memory safety bugs fixed in Firefox 60.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause denial of service condition, bypass security restrictions, execute
  arbitrary code and disclose sensitive information.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 60 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 60
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-11/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");
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

exit(99);
