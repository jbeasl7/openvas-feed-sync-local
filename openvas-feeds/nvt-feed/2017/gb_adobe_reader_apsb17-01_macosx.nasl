# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810335");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2017-2939", "CVE-2017-2940", "CVE-2017-2941", "CVE-2017-2942",
                "CVE-2017-2943", "CVE-2017-2944", "CVE-2017-2945", "CVE-2017-2946",
                "CVE-2017-2947", "CVE-2017-2948", "CVE-2017-2949", "CVE-2017-2950",
                "CVE-2017-2951", "CVE-2017-2952", "CVE-2017-2953", "CVE-2017-2954",
                "CVE-2017-2955", "CVE-2017-2956", "CVE-2017-2957", "CVE-2017-2958",
                "CVE-2017-2959", "CVE-2017-2960", "CVE-2017-2961", "CVE-2017-2962",
                "CVE-2017-2963", "CVE-2017-2964", "CVE-2017-2965", "CVE-2017-2966",
                "CVE-2017-2967", "CVE-2017-2970", "CVE-2017-2971", "CVE-2017-2972",
                "CVE-2017-3009", "CVE-2017-3010");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-22 14:36:00 +0000 (Wed, 22 May 2019)");
  script_tag(name:"creation_date", value:"2017-01-11 08:28:14 +0530 (Wed, 11 Jan 2017)");
  script_name("Adobe Reader Security Updates (APSB17-01) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Reader is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A type confusion vulnerability.

  - An use-after-free vulnerabilities.

  - The heap buffer overflow vulnerabilities.

  - The buffer overflow vulnerabilities.

  - The memory corruption vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities will allow remote attackers to do code execution,
  security bypass and information disclosure.");

  script_tag(name:"affected", value:"Adobe Reader version 11.x before
  11.0.19 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Reader version
  11.0.19 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb17-01.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Reader/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!readerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:readerVer, test_version:"11.0", test_version2:"11.0.18"))
{
  report = report_fixed_ver(installed_version:readerVer, fixed_version:"11.0.19");
  security_message(data:report);
  exit(0);
}
