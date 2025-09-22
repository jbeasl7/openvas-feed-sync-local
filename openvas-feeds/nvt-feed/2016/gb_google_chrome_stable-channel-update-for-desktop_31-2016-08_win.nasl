# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809032");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2016-5147", "CVE-2016-5148", "CVE-2016-5149", "CVE-2016-5150",
                "CVE-2016-5151", "CVE-2016-5152", "CVE-2016-5153", "CVE-2016-5154",
                "CVE-2016-5155", "CVE-2016-5156", "CVE-2016-5157", "CVE-2016-5158",
                "CVE-2016-5159", "CVE-2016-5161", "CVE-2016-5162", "CVE-2016-5163",
                "CVE-2016-5164", "CVE-2016-5165", "CVE-2016-5166", "CVE-2016-5160",
                "CVE-2016-5167", "CVE-2016-7395");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-09-06 14:41:40 +0530 (Tue, 06 Sep 2016)");
  script_name("Google Chrome Security Updates (stable-channel-update-for-desktop_31-2016-08) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An address bar spoofing vulnerability.

  - Multiple use-after-free errors in Blink.

  - Multiple heap overflow errors in pdfium.

  - Multiple universal xss errors in Blink.

  - A type confusion error in Blink.

  - A script injection error in DevTools.

  - An universal xss error in DevTools.

  - A smb relay Attack via Save Page As.

  - An extensions web accessible resources bypass

  - The SkPath.cpp in Skia does not properly validate the return values of
    ChopMonoAtY calls.

  - The various fixes from internal audits, fuzzing and other initiatives.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to conduct spoofing attacks on a
  targeted system, to bypass security, to corrupt memory, to execute arbitrary
  code, to escalate privileges and to cause denial of service condition.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  53.0.2785.89 on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  53.0.2785.89 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2016/08/stable-channel-update-for-desktop_31.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92717");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!chr_ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chr_ver, test_version:"53.0.2785.89"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"53.0.2785.89");
  security_message(data:report);
  exit(0);
}
