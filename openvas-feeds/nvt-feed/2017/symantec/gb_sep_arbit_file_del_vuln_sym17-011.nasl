# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symantec:endpoint_protection";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812069");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2017-13680");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-11-08 15:56:13 +0530 (Wed, 08 Nov 2017)");
  script_name("Symantec Endpoint Protection Arbitrary File Deletion Vulnerability (SYM17-011)");

  script_tag(name:"summary", value:"Symantec Endpoint Protection is prone to arbitrary file deletion vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to unspecified error
  within the application.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to use the product's UI to perform unauthorized file deletes on the resident file
  system.");

  script_tag(name:"affected", value:"Symantec Endpoint Protection prior to SEP
  12.1 RU6 MP9 and prior to SEP 14 RU1");

  script_tag(name:"solution", value:"Upgrade to SEP 12.1 RU6 MP9 or 14 RU1 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20171106_00");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101503");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("secpod_symantec_prdts_detect.nasl");
  script_mandatory_keys("Symantec/Endpoint/Protection");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
sepVer = infos["version"];
sepPath = infos["location"];


## 12.1 RU 6 MP8 == 12.1.7266.6800 (https://symwisedownload.symantec.com//resources/sites/SYMWISE/content/live/DOCUMENTATION/10000/DOC10664/en_US/Release_Notes_SEP12.1.6.9.pdf?__gda__=1510259634_5c951540545a10df49506b622a48bd42)
## Symantec Endpoint Protection 14.0.1 (14 RU1) is the next release after version 14 MP2
## 14 MP2 == 14.0.2415.0200 (https://symwisedownload.symantec.com//resources/sites/SYMWISE/content/live/DOCUMENTATION/10000/DOC10647/en_US/Release_Notes_SEP14.0.1_14.1.pdf?__gda__=1510269710_1109370072d2e4fd90dffcbaae4e2737)
if(version_is_less_equal(version:sepVer, test_version:"12.1.7266.6800")){
  fix = "12.1 RU 6 MP9";
} else if(version_in_range(version:sepVer, test_version:"14.0", test_version2:"14.0.2415.0200")){
  fix = "14 RU1";
}

if(fix)
{
  report = report_fixed_ver(installed_version:sepVer, fixed_version:fix, install_path:sepPath);
  security_message(data:report);
  exit(0);
}
exit(0);
