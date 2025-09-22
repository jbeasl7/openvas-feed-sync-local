# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806512");
  script_version("2024-02-20T14:37:13+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2015-4902", "CVE-2015-4903", "CVE-2015-4911", "CVE-2015-4893",
                "CVE-2015-4883", "CVE-2015-4882", "CVE-2015-4881", "CVE-2015-4872",
                "CVE-2015-4860", "CVE-2015-4844", "CVE-2015-4843", "CVE-2015-4842",
                "CVE-2015-4835", "CVE-2015-4806", "CVE-2015-4805", "CVE-2015-4803",
                "CVE-2015-4734");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-20 14:37:13 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-10-27 11:40:31 +0530 (Tue, 27 Oct 2015)");
  script_name("Oracle Java SE JRE Multiple Unspecified Vulnerabilities-02 (Oct 2015) - Windows");

  script_tag(name:"summary", value:"Oracle Java SE JRE is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple
  unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to have an impact on confidentiality, integrity, and availability via different
  vectors.");

  script_tag(name:"affected", value:"Oracle Java SE 6 update 101 and prior, 7
  update 85 and prior, 8 update 60 and prior on Windows.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/alerts-086861.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77241");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77194");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77209");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77207");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77161");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77181");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77159");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77211");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77162");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77164");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77160");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77154");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77148");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77126");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77163");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77200");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77192");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:oracle:jre", "cpe:/a:sun:jre");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^1\.[6-8]") {
  if(version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.0.60") ||
     version_in_range(version:vers, test_version:"1.7.0", test_version2:"1.7.0.85") ||
     version_in_range(version:vers, test_version:"1.6.0", test_version2:"1.6.0.101")) {
    report = 'Installed version: ' + vers + '\n' +
             'Fixed version:     ' + "Apply the patch"  + '\n';
    security_message(data:report);
    exit(0);
  }
}
