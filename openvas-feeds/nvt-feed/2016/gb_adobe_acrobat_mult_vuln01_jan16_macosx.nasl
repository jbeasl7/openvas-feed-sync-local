# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806819");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2016-0931", "CVE-2016-0932", "CVE-2016-0933", "CVE-2016-0934",
                "CVE-2016-0935", "CVE-2016-0936", "CVE-2016-0937", "CVE-2016-0938",
                "CVE-2016-0939", "CVE-2016-0940", "CVE-2016-0941", "CVE-2016-0942",
                "CVE-2016-0943", "CVE-2016-0944", "CVE-2016-0945", "CVE-2016-0946",
                "CVE-2016-0947", "CVE-2016-1111");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-07 23:41:00 +0000 (Wed, 07 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-01-18 13:37:18 +0530 (Mon, 18 Jan 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Adobe Acrobat Multiple Vulnerabilities - 01 (Jan 2016) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Acrobat is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Untrusted search path vulnerability in Adobe Download Manager

  - Some use-after-free vulnerabilities.

  - A double-free vulnerability.

  - Some memory leak vulnerabilities.

  - Some security bypass vulnerabilities.

  - Multiple memory corruption vulnerabilities.

  - Some Javascript API execution restriction bypass vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to bypass certain access restrictions and execute arbitrary
  code and compromise a user's system.");

  script_tag(name:"affected", value:"Adobe Acrobat 11.x before 11.0.14 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Acrobat version 11.0.14 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb16-02.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Acrobat/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!readerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:readerVer, test_version:"11.0", test_version2:"11.0.13"))
{
  report = report_fixed_ver(installed_version:readerVer, fixed_version:"11.0.14");
  security_message(data:report);
  exit(0);
}
