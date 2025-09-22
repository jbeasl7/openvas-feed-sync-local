# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801825");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-01-27 07:47:27 +0100 (Thu, 27 Jan 2011)");
  script_cve_id("CVE-2011-0470", "CVE-2011-0471", "CVE-2011-0472", "CVE-2011-0473",
                "CVE-2011-0474", "CVE-2011-0475", "CVE-2011-0476", "CVE-2011-0477",
                "CVE-2011-0478", "CVE-2011-0479", "CVE-2011-0480", "CVE-2011-0481",
                "CVE-2011-0482", "CVE-2011-0483", "CVE-2011-0484", "CVE-2011-0485");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Google Chrome Multiple Vulnerabilities (Jan 2011) - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42850/");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/01/chrome-stable-release.html");

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause a denial of service.");
  script_tag(name:"affected", value:"Google Chrome version prior to 8.0.552.237 on windows");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An unspecified error exists within the extensions notification handling.

  - An unspecified error exists when handling pointers within node iteration.

  - An unspecified error exists when printing multi-page PDF files.

  - An error when handling CSS and canvas can be exploited to reference a stale
    pointer.

  - An error when handling CSS and cursors can be exploited to reference a stale
    pointer.

  - A use-after-free error when handling PDF pages can be exploited to reference
    freed memory.

  - An error due to an out-of-memory condition when processing PDF files can be
    exploited to cause stack corruption.

  - An error when handling mismatched video frame sizes can be exploited to
    reference invalid memory.

  - An error when handling SVG '<use>' elements can be exploited to reference
    a stale pointer.

  - An error when handling rogue extensions can be exploited to reference an
    uninitialised pointer.

  - An error within the Vorbis decoder can be exploited to cause a buffer
    overflow.

  - An error within PDF shading can be exploited to cause a buffer overflow.

  - An error when handling anchors may result in an incorrect type cast.

  - An error when handling videos may result in an incorrect type cast.

  - An error after removal of a DOM node may result in a stale rendering node.

  - An error when handling speech can be exploited to reference a stale pointer.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 8.0.552.237 or later.");
  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"8.0.552.237")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"8.0.552.237");
  security_message(port: 0, data: report);
}
