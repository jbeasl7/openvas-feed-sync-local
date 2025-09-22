# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804368");
  script_version("2024-11-22T15:40:47+0000");
  script_cve_id("CVE-2009-2564");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"creation_date", value:"2014-04-08 16:15:57 +0530 (Tue, 08 Apr 2014)");
  script_name("Adobe Reader 'Download Manager' Privilege Escalation Vulnerability - Windows");

  script_tag(name:"summary", value:"Adobe Reader is prone to a privilege escalation vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw is due to insecure permissions being set on the NOS installation
directory within Corel getPlus Download Manager.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain escalated privileges on
the system.");
  script_tag(name:"affected", value:"Adobe Reader 7.x before 7.1.4, 8.x before 8.1.7 and 9.x before 9.2 on
Windows.");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader 7.1.4 or 8.1.7 or 9.2 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35930");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35740");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1023007");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/9199");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54383");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb09-15.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Reader/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(vers && vers =~ "^[7-9]\.") {
  if(version_in_range(version:vers, test_version:"9.0", test_version2:"9.1.3")||
     version_in_range(version:vers, test_version:"8.0", test_version2:"8.1.6")||
     version_in_range(version:vers, test_version:"7.0", test_version2:"7.1.3"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
