# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:jre";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805722");
  script_version("2024-07-17T05:05:38+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2015-4760", "CVE-2015-4749", "CVE-2015-4748", "CVE-2015-4733",
                "CVE-2015-4732", "CVE-2015-4731", "CVE-2015-2664", "CVE-2015-2638",
                "CVE-2015-2637", "CVE-2015-2621", "CVE-2015-2625", "CVE-2015-2627",
                "CVE-2015-2628", "CVE-2015-2632", "CVE-2015-2601", "CVE-2015-2590");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-17 05:05:38 +0000 (Wed, 17 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:43:11 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2015-07-20 17:10:19 +0530 (Mon, 20 Jul 2015)");
  script_name("Oracle Java SE JRE Multiple Unspecified Vulnerabilities-01 (Jul 2015) - Windows");

  script_tag(name:"summary", value:"Oracle Java SE JRE is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple errors exist due to unspecified
  flaws related to multiple unspecified vectors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to have an impact on confidentiality, integrity, and availability.");

  script_tag(name:"affected", value:"Oracle Java SE 6 update 95, 7 update 80,
  8 update 45 on Windows.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75784");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75890");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75854");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75832");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75823");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75812");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75857");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75833");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75883");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75874");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75895");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75893");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75796");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75861");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75867");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75818");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!jreVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(jreVer =~ "^(1\.(6|8|7))")
{
  if(version_in_range(version:jreVer, test_version:"1.6.0", test_version2:"1.6.0.95")||
     version_in_range(version:jreVer, test_version:"1.7.0", test_version2:"1.7.0.80")||
     version_in_range(version:jreVer, test_version:"1.8.0", test_version2:"1.8.0.45"))
  {
    report = report_fixed_ver(installed_version:jreVer, fixed_version: "Apply the patch from the referenced advisory.");
    security_message(data:report);
    exit(0);
  }
}
