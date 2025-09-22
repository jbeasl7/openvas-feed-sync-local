# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806692");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2016-1779", "CVE-2016-1771", "CVE-2016-1772", "CVE-2016-1762",
                "CVE-2009-2197", "CVE-2016-1786", "CVE-2016-1785", "CVE-2016-1784",
                "CVE-2016-1782", "CVE-2016-1783", "CVE-2016-1781", "CVE-2016-1778",
                "CVE-2016-1864");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-25 17:38:00 +0000 (Mon, 25 Mar 2019)");
  script_tag(name:"creation_date", value:"2016-04-01 13:19:23 +0530 (Fri, 01 Apr 2016)");
  script_name("Apple Safari Multiple Vulnerabilities-01 (Mar 2016) - Mac OS X");

  script_tag(name:"summary", value:"Apple Safari is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An insufficient input validation issue in the handling of certain files.

  - An error where the text of a dialog included page-supplied text.

  - A cookie storage issue existed in the Top Sites page.

  - An issue in the handling of attachment URLs.

  - Multiple memory corruption issue.

  - A port redirection issue.

  - An issue in the parsing of geolocation requests.

  - A resource exhaustion issue.

  - A caching issue with character encoding.

  - An error allowing URL redirection.

  - An error in the libxml2 leading to processing of maliciously crafted XML.

  - The XSS auditor in WebKit does not properly handle redirects in block mode.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct application crash or denial of service attack, user
  interface spoofing, gain access to sensitive information, access restricted
  ports, conduct data cross-origin attacks and potentially execute arbitrary
  code on the affected system.");

  script_tag(name:"affected", value:"Apple Safari versions before 9.1");

  script_tag(name:"solution", value:"Upgrade to Apple Safari version 9.1 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT206171");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

if(version_is_less(version:safVer, test_version:"9.1"))
{
  report = report_fixed_ver(installed_version:safVer, fixed_version:"9.1");
  security_message(data:report);
  exit(0);
}
