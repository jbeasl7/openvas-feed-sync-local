# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:bullguard:internet_security";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805276");
  script_version("2024-11-22T15:40:47+0000");
  script_cve_id("CVE-2014-9642");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"creation_date", value:"2015-02-12 19:10:23 +0530 (Thu, 12 Feb 2015)");
  script_name("BullGuard Internet Security 'BdAgent.sys' Driver Privilege Escalation Vulnerability");

  script_tag(name:"summary", value:"BullGuard Internet Security is prone to a local privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in the
  BdAgent.sys driver that is triggered when handling various IOCTLs");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attacker to write data to an arbitrary memory location, leading to code
  execution with kernel-level privileges.");

  script_tag(name:"affected", value:"BullGuard Internet Security before
  version 15.0.288");

  script_tag(name:"solution", value:"Upgrade to BullGuard Internet Security
  version 15.0.288 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.greyhathacker.net/?p=818");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/35994");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/130247");
  script_xref(name:"URL", value:"http://www.bullguard.com/about/release-notes.aspx");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Privilege escalation");
  script_dependencies("gb_bullguard_internet_security_detect.nasl");
  script_mandatory_keys("BullGuard/Internet/Security/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!bullVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:bullVer, test_version:"15.0.288.0"))
{
  report = 'Installed version: ' + bullVer + '\n' +
           'Fixed version:     ' + '15.0.288.0' + '\n';
  security_message(data:report);
  exit(0);
}
