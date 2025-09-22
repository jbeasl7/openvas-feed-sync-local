# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803879");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2013-2887", "CVE-2013-2900", "CVE-2013-2901", "CVE-2013-2902",
                "CVE-2013-2903", "CVE-2013-2904", "CVE-2013-2905");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-08-26 13:05:48 +0530 (Mon, 26 Aug 2013)");
  script_name("Google Chrome Multiple Vulnerabilities-01 (Aug 2013) - Mac OS X");
  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to version 29.0.1547.57 or later.");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Some unspecified errors exist.

  - An error exists when handling file paths.

  - An integer overflow error exists within ANGLE.

  - Insecure permissions when creating certain shared memory files.

  - Use-after-free error exists within XSLT, media element and document parsing.");
  script_tag(name:"affected", value:"Google Chrome version prior to 29.0.1547.57 on Mac OS X.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to disclose potentially sensitive information, compromise a user's system and other attacks may also be possible.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54479");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61885");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61886");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61887");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61888");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61889");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61890");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61891");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2013/08/stable-channel-update.html");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");

  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("GoogleChrome/MacOSX/Version");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"29.0.1547.57"))
{
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"29.0.1547.57");
  security_message(port: 0, data: report);
  exit(0);
}
