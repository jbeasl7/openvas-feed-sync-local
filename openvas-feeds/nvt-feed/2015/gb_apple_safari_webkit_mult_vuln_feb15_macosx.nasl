# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805336");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2014-4479", "CVE-2014-4477", "CVE-2014-4476");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-02-09 18:15:32 +0530 (Mon, 09 Feb 2015)");
  script_name("Apple Safari 'Webkit' Multiple Vulnerabilities -01 (Feb 2015) - Mac OS X");

  script_tag(name:"summary", value:"Apple Safari is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple errors exist as user-supplied
  input is not properly validated and an use-after-free error exists that is
  triggered when handling Set objects.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to conduct denial of service attack and potentially execute
  arbitrary code.");

  script_tag(name:"affected", value:"Apple Safari versions before 6.2.3, 7.x
  before 7.1.3 and 8.x before 8.0.3");

  script_tag(name:"solution", value:"Upgrade to Apple Safari version 6.2.3 or
  7.1.3 or 8.0.3.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"http://support.apple.com/en-us/HT204243");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72330");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72331");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72329");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2015/Jan/msg00002.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!safVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:safVer, test_version:"6.2.3"))
{
  fix = "6.2.3";
  VULN = TRUE;
}

if(version_in_range(version:safVer, test_version:"7.0", test_version2:"7.1.2"))
{
  fix = "7.1.3";
  VULN = TRUE;
}

if(version_in_range(version:safVer, test_version:"8.0", test_version2:"8.0.2"))
{
  fix = "8.0.3";
  VULN = TRUE;
}

if(VULN)
{
  report = 'Installed version: ' + safVer + '\n' +
           'Fixed version:     ' + fix + '\n';
  security_message(data:report);
  exit(0);
}
