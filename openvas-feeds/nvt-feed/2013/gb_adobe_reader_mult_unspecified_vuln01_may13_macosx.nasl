# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803614");
  script_version("2024-07-10T05:05:27+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-3342", "CVE-2013-3341", "CVE-2013-3340", "CVE-2013-3339",
                "CVE-2013-3338", "CVE-2013-3337", "CVE-2013-2737", "CVE-2013-2736",
                "CVE-2013-2735", "CVE-2013-2734", "CVE-2013-2733", "CVE-2013-2732",
                "CVE-2013-2731", "CVE-2013-2730", "CVE-2013-2729", "CVE-2013-2727",
                "CVE-2013-2726", "CVE-2013-2725", "CVE-2013-2724", "CVE-2013-2723",
                "CVE-2013-2722", "CVE-2013-2721", "CVE-2013-2720", "CVE-2013-2719",
                "CVE-2013-2718", "CVE-2013-3346", "CVE-2013-2549", "CVE-2013-2550");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-10 05:05:27 +0000 (Wed, 10 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-09 18:22:32 +0000 (Tue, 09 Jul 2024)");
  script_tag(name:"creation_date", value:"2013-05-28 10:15:11 +0530 (Tue, 28 May 2013)");
  script_name("Adobe Reader Multiple Unspecified Vulnerabilities -01 (May 2013) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Reader is prone to multiple unspecified vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Please see the references for more information on the vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code,
corrupt memory, obtain sensitive information, bypass certain security
restrictions or cause a denial of service condition.");
  script_tag(name:"affected", value:"Adobe Reader Version 9.x prior to 9.5.5 on Mac OS X
Adobe Reader X Version 10.x prior to 10.1.7 on Mac OS X
Adobe Reader XI Version 11.x prior to 11.0.03 on Mac OS X");
  script_tag(name:"solution", value:"Update to Adobe Reader Version 11.0.03 or 10.1.7 or 9.5.5 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/53420");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58398");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58568");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59902");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59903");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59904");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59905");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59906");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59907");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59908");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59909");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59910");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59911");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59912");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59913");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59914");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59915");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59916");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59917");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59918");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59919");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59920");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59921");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59923");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59925");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59926");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59927");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59930");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-15.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Reader/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(vers =~ "^(9|1[01])\.")
{
  if((version_in_range(version:vers, test_version:"9.0", test_version2: "9.5.4"))||
     (version_in_range(version:vers, test_version:"10.0", test_version2: "10.1.6"))||
     (version_in_range(version:vers, test_version:"11.0", test_version2: "11.0.02")))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
