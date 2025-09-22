# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symantec:norton_antivirus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808511");
  script_version("2023-11-03T05:05:46+0000");
  script_cve_id("CVE-2016-2207", "CVE-2016-2209", "CVE-2016-2210", "CVE-2016-2211",
                "CVE-2016-3644", "CVE-2016-3645", "CVE-2016-3646");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-11 19:23:00 +0000 (Mon, 11 May 2020)");
  script_tag(name:"creation_date", value:"2016-07-04 16:11:01 +0530 (Mon, 04 Jul 2016)");
  script_name("Symantec Norton AntiVirus Decomposer Engine Multiple Parsing Vulnerabilities");

  script_tag(name:"summary", value:"Symantec Norton AntiVirus is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to an error in
  Parsing of maliciously-formatted container files in Symantecs Decomposer engine.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause memory corruption, integer overflow or buffer overflow results in an
  application-level denial of service.");

  script_tag(name:"affected", value:"Symantec Norton AntiVirus NGC 22.7 and prior.");

  script_tag(name:"solution", value:"Update Symantec Norton AntiVirus
  through LiveUpdate.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20160628_00");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91434");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91436");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91437");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91438");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91431");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91439");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91435");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("secpod_symantec_prdts_detect.nasl");
  script_mandatory_keys("Symantec/Norton-AV/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!sepVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Symantec Norton AntiVirus after LiveUpdate (22.7.0.76)
if(version_is_less(version:sepVer, test_version:"22.7.0.76"))
{
  report = report_fixed_ver(installed_version:sepVer, fixed_version:"22.7.0.76");
  security_message(data:report);
  exit(0);
}

