# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:bitdefender:internet_security";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810940");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-6186");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-05-04 10:27:21 +0530 (Thu, 04 May 2017)");
  script_name("Bitdefender Internet Security DLL Loading Local Code Injection Vulnerability");

  script_tag(name:"summary", value:"Bitdefender Internet Security is prone to local code injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the product do not
  use the Protected Processes feature, and therefore an attacker can enter an
  arbitrary Application Verifier Provider DLL under Image File Execution Options
  in the registry. The self-protection mechanism is intended to block all local
  processes (regardless of privileges) from modifying Image File Execution Options
  for this product. This mechanism can be bypassed by an attacker who
  temporarily renames Image File Execution Options during the attack.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attacker to bypass a self-protection mechanism, inject arbitrary code, and take
  full control of any Bitdefender process via a 'DoubleAgent' attack.");

  script_tag(name:"affected", value:"Bitdefender Internet Security 12.0
  (and earlier).");

  script_tag(name:"solution", value:"Update Bitdefender to the latest version and ensure that the build version matches at least the following version: 21.0.24.62");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://cybellum.com/doubleagent-taking-full-control-antivirus");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97024");
  script_xref(name:"URL", value:"http://cybellum.com/doubleagentzero-day-code-injection-and-persistence-technique");
  script_xref(name:"URL", value:"https://forum.bitdefender.com/index.php?/topic/75470-doubleagent/");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_bitdefender_prdts_detect.nasl");
  script_mandatory_keys("BitDefender/InetSec/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!bitVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less_equal(version:bitVer, test_version:"12.0"))
{
  report = report_fixed_ver(installed_version:bitVer, fixed_version:"Build: 21.0.24.62");
  security_message(data:report);
  exit(0);
}
