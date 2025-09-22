# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:avast:avast_pro_antivirus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810900");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-5567");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-04-05 10:13:58 +0530 (Wed, 05 Apr 2017)");
  script_name("Avast Pro DoubleAgent Attack Local Code Injection Vulnerability");

  script_tag(name:"summary", value:"Avast Pro is prone to local code injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the product do not
  use the Protected Processes feature, and therefore an attacker can enter an
  arbitrary Application Verifier Provider DLL under Image File Execution Options
  in the registry. The self-protection mechanism is intended to block all local
  processes (regardless of privileges) from modifying Image File Execution Options
  for this producti.This mechanism can be bypassed by an attacker who
  temporarily renames Image File Execution Options during the attack.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attacker to execute arbitrary code in the context of the system running the
  affected application. This can also result in the attacker gaining complete
  control of the affected application.");

  script_tag(name:"affected", value:"Avast Pro versions prior to 17.0");

  script_tag(name:"solution", value:"Upgrade to Avast Pro version
  17.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://forum.avast.com/index.php?topic=199290.0");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97017");
  script_xref(name:"URL", value:"http://feeds.security-database.com/~r/Last100Alerts/~3/M6mwzAVFo-U/detail.php");
  script_xref(name:"URL", value:"https://www.engadget.com/2017/03/21/doubleagent-attack-anti-virus-hijack-your-pc");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_avast_pro_detect.nasl");
  script_mandatory_keys("Avast/Pro_Antivirus/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!avastVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:avastVer, test_version:"17.0"))
{
  report = report_fixed_ver(installed_version:avastVer, fixed_version:"17.0");
  security_message(data:report);
  exit(0);
}

exit(99);
