# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:k7computing:anti-virus_plus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805455");
  script_version("2024-11-22T15:40:47+0000");
  script_cve_id("CVE-2014-9643");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"creation_date", value:"2015-01-27 17:11:51 +0530 (Tue, 27 Jan 2015)");
  script_tag(name:"qod_type", value:"registry");
  script_name("K7 Anti-Virus Plus Privilege Escalation Vulnerability (Feb 2015) - Windows");

  script_tag(name:"summary", value:"K7 Anti-Virus Plus is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a write-what-where flaw
  in K7Sentry.sys in K7 Computing products that is triggered when handling
  certain IOCTL calls.");

  script_tag(name:"impact", value:"Successful exploitation will allow a local
  attacker to write controlled data to any memory location and execute code with
  kernel-level privileges.");

  script_tag(name:"affected", value:"K7 Anti-Virus Plus before 14.2.0.253
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to K7 Anti-Virus Plus version
  14.2.0.253 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/35992/");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/130246/");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Privilege escalation");
  script_dependencies("gb_k7_anti_virus_plus_detect_win.nasl");
  script_mandatory_keys("K7/AntiVirusPlus/Win/Installed");
  script_xref(name:"URL", value:"http://www.k7computing.co.uk");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!k7antivirVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:k7antivirVer, test_version:"14.2.0.253"))
{
  report = 'Installed version: ' + k7antivirVer + '\n' +
             'Fixed version:     ' + "14.2.0.253" + '\n';
  security_message(data:report );
  exit(0);
}

exit(99);
