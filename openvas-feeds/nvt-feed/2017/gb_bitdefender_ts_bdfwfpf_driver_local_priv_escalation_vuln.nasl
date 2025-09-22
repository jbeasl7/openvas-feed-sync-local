# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:bitdefender:total_security";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811803");
  script_version("2024-11-22T15:40:47+0000");
  script_cve_id("CVE-2017-10950");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:21:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-09-05 16:45:12 +0530 (Tue, 05 Sep 2017)");
  script_name("Bitdefender Total Security 'bdfwfpf' Kernel Driver Privilege Escalation Vulnerability");

  script_tag(name:"summary", value:"Bitdefender Total Security is prone to a local privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error with the
  processing of the 0x8000E038 IOCTL in the bdfwfpf driver. The issue results
  from the lack of validating the existence of an object prior to performing
  operations on the object.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attacker to execute arbitrary code in the context of SYSTEM with elevated
  privileges.");

  script_tag(name:"affected", value:"Bitdefender Total Security 21.0.24.62.");

  script_tag(name:"solution", value:"Update to version 21.2.25.30 (AV 2017), 22.0.8.114 (AV 2018) or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100418");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-17-693/");

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Privilege escalation");
  script_dependencies("secpod_bitdefender_prdts_detect.nasl");
  script_mandatory_keys("BitDefender/TotalSec/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!bitVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(bitVer == "21.0.24.62")
{
  report = report_fixed_ver(installed_version:bitVer, fixed_version:"21.2.25.30");
  security_message(data:report);
  exit(0);
}

exit(0);
