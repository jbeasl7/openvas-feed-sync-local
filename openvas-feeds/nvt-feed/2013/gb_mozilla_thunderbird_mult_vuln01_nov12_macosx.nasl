# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803363");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2012-4209", "CVE-2012-4214", "CVE-2012-4215", "CVE-2012-4216",
                "CVE-2012-4201", "CVE-2012-4202", "CVE-2012-4207", "CVE-2012-5842",
                "CVE-2012-5841", "CVE-2012-5829", "CVE-2012-5830", "CVE-2012-5833",
                "CVE-2012-5835", "CVE-2012-5839", "CVE-2012-5840");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-13 17:31:00 +0000 (Thu, 13 Aug 2020)");
  script_tag(name:"creation_date", value:"2012-11-26 11:10:03 +0530 (Mon, 26 Nov 2012)");
  script_name("Mozilla Thunderbird Multiple Vulnerabilities-01 (Nov 2012) - Mac OS X");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51358");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56611");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56614");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56618");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56628");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56629");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56631");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56632");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56633");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56634");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56635");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56636");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56637");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56641");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56642");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027791");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027792");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-91.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-92.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-93.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-100.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-101.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-103.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-105.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2012/mfsa2012-106.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Thunderbird/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to inject scripts, bypass
  certain security restrictions, execute arbitrary code in the context of the
  browser.");
  script_tag(name:"affected", value:"Thunderbird version before 17.0 on Mac OS X");
  script_tag(name:"insight", value:"- The 'location' property can be accessed through 'top.location' with a
    frame whose name attributes value is set to 'top'.

  - Use-after-free error exists within the functions
    'nsTextEditorState::PrepareEditor', 'gfxFont::GetFontEntry',
    'nsWindow::OnExposeEvent' and 'nsPlaintextEditor::FireClipboardEvent'.

  - An error within the 'evalInSandbox()' when handling the 'location.href'
    property.

  - Error when rendering GIF images.");
  script_tag(name:"solution", value:"Upgrade to Thunderbird version to 17.0 or later.");
  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

vers = get_kb_item("Thunderbird/MacOSX/Version");
if(vers)
{
  if(version_is_less(version:vers, test_version:"17.0"))
  {
    report = report_fixed_ver(installed_version:vers, fixed_version:"17.0");
    security_message(port: 0, data: report);
    exit(0);
  }
}
