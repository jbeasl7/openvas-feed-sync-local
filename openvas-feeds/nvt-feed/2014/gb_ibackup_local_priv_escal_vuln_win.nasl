# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pro_softnet_corporation:ibackup";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805200");
  script_version("2024-11-22T15:40:47+0000");
  script_cve_id("CVE-2014-5507");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"creation_date", value:"2014-12-01 12:04:33 +0530 (Mon, 01 Dec 2014)");
  script_name("iBackup Local Privilege Escalation Vulnerability - Windows");

  script_tag(name:"summary", value:"iBackup is prone to a local privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw exists as the program uses insecure
  permissions which can allow anyone to replace the ib_service.exe with an
  executable of their choice that is loaded on system or service restart.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attacker to gain elevated privileges.");

  script_tag(name:"affected", value:"iBackup version 10.0.0.32 and prior on
  Windows.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");
  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/35040");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70724");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/128806/");

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Privilege escalation");
  script_dependencies("gb_ibackup_detect_win.nasl");
  script_mandatory_keys("iBackup/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!iBackupVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less_equal(version:iBackupVer, test_version:"10.0.0.32"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
