# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809805");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2016-5296", "CVE-2016-5292", "CVE-2016-5293", "CVE-2016-5294",
                "CVE-2016-5297", "CVE-2016-9064", "CVE-2016-9066", "CVE-2016-9067",
                "CVE-2016-5290", "CVE-2016-9068", "CVE-2016-5289", "CVE-2016-9075",
                "CVE-2016-9077", "CVE-2016-5291", "CVE-2016-5295", "CVE-2016-9070",
                "CVE-2016-9073", "CVE-2016-9074", "CVE-2016-9076", "CVE-2016-9063",
                "CVE-2016-9071");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-30 12:53:00 +0000 (Mon, 30 Jul 2018)");
  script_tag(name:"creation_date", value:"2016-11-16 12:21:41 +0530 (Wed, 16 Nov 2016)");
  script_name("Mozilla Firefox Security Advisories (MFSA2016-89, MFSA2016-90) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Heap-buffer-overflow WRITE in rasterize_edges_1.

  - URL parsing causes crash.

  - Write to arbitrary file with Mozilla Updater and Maintenance Service using
    updater.log hardlink.

  - Arbitrary target directory for result files of update process.

  - Incorrect argument length checking in JavaScript.

  - Add-ons update must verify IDs match between current and new versions.

  - Integer overflow leading to a buffer overflow in nsScriptLoadHandler.

  - heap-use-after-free in nsINode::ReplaceOrInsertBefore.

  - heap-use-after-free in nsRefreshDriver.

  - WebExtensions can access the mozAddonManager API and use it to gain elevated
    privileges.

  - Canvas filters allow feDisplacementMaps to be applied to cross-origin images,
    allowing timing attacks on them.

  - Same-origin policy violation using local HTML file and saved shortcut file.

  - Mozilla Maintenance Service: Ability to read arbitrary files as SYSTEM.

  - Sidebar bookmark can have reference to chrome window.

  - Insufficient timing side-channel resistance in divSpoiler.

  - select dropdown menu can be used for URL bar spoofing on e10s.

  - Possible integer overflow to fix inside XML_Parse in Expat.

  - Probe browser history via HSTS/301 redirect + CSP.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to execute arbitrary code, to delete
  arbitrary files by leveraging certain local file execution, to obtain sensitive
  information, and to cause a denial of service.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 50 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 50
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-89/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94336");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94337");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94342");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94339");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
   exit(0);
}

if(version_is_less(version:ffVer, test_version:"50.0"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"50.0");
  security_message(data:report);
  exit(0);
}
