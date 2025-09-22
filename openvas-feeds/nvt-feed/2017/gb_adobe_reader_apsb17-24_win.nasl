# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811618");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2017-3016", "CVE-2017-3038", "CVE-2017-3113", "CVE-2017-3115",
                "CVE-2017-3116", "CVE-2017-3117", "CVE-2017-3118", "CVE-2017-3119",
                "CVE-2017-3120", "CVE-2017-3121", "CVE-2017-3122", "CVE-2017-3123",
                "CVE-2017-3124", "CVE-2017-11209", "CVE-2017-11210", "CVE-2017-11211",
                "CVE-2017-11212", "CVE-2017-11214", "CVE-2017-11216", "CVE-2017-11217",
                "CVE-2017-11218", "CVE-2017-11219", "CVE-2017-11220", "CVE-2017-11221",
                "CVE-2017-11222", "CVE-2017-11223", "CVE-2017-11224", "CVE-2017-11226",
                "CVE-2017-11227", "CVE-2017-11228", "CVE-2017-11229", "CVE-2017-11230",
                "CVE-2017-11231", "CVE-2017-11232", "CVE-2017-11233", "CVE-2017-11234",
                "CVE-2017-11235", "CVE-2017-11236", "CVE-2017-11237", "CVE-2017-11238",
                "CVE-2017-11239", "CVE-2017-11241", "CVE-2017-11242", "CVE-2017-11243",
                "CVE-2017-11244", "CVE-2017-11245", "CVE-2017-11246", "CVE-2017-11248",
                "CVE-2017-11249", "CVE-2017-11251", "CVE-2017-11252", "CVE-2017-11254",
                "CVE-2017-11255", "CVE-2017-11256", "CVE-2017-11257", "CVE-2017-11258",
                "CVE-2017-11259", "CVE-2017-11260", "CVE-2017-11261", "CVE-2017-11262",
                "CVE-2017-11263", "CVE-2017-11265", "CVE-2017-11267", "CVE-2017-11268",
                "CVE-2017-11269", "CVE-2017-11270", "CVE-2017-11271");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-21 16:19:00 +0000 (Wed, 21 Aug 2019)");
  script_tag(name:"creation_date", value:"2017-08-10 10:47:06 +0530 (Thu, 10 Aug 2017)");
  script_name("Adobe Reader Security Updates (APSB17-24) - Windows");

  script_tag(name:"summary", value:"Adobe Reader is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple memory corruption vulnerabilities.

  - Multiple use after free vulnerabilities.

  - Multiple Security Bypass vulnerabilities.

  - Multiple Type Confusion vulnerabilities.

  - Multiple heap overflow vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to execute arbitrary code remotely and can get
  hands on sensitive information.");

  script_tag(name:"affected", value:"Adobe Reader version 11.x before 11.0.21
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Reader version 11.0.21 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb17-24.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100179");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97556");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100182");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100187");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100180");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100189");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100184");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100181");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100186");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100185");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Reader/Win/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!readerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:readerVer, test_version:"11.0", test_version2:"11.0.20"))
{
  report = report_fixed_ver(installed_version:readerVer, fixed_version:"11.0.21");
  security_message(data:report);
  exit(0);
}
