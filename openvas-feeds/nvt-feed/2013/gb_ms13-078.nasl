# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:frontpage";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903321");
  script_version("2025-07-11T15:43:14+0000");
  script_cve_id("CVE-2013-3137");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-07-11 15:43:14 +0000 (Fri, 11 Jul 2025)");
  script_tag(name:"creation_date", value:"2013-09-11 11:12:46 +0530 (Wed, 11 Sep 2013)");
  script_name("Microsoft FrontPage Information Disclosure Vulnerability (2825621)");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS13-078.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified information disclosure
  vulnerability.");

  script_tag(name:"affected", value:"Microsoft FrontPage 2003 Service Pack 3.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to disclose the
  contents of a file on a target system.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2825621");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62185");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-078");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_frontpage_smb_login_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("microsoft/frontpage/smb-login/detected");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

if(isnull(port = get_app_port(cpe:CPE, service:"smb-login")))
  exit(0);

if(!path = get_app_location(cpe:CPE, port:port))
  exit(0);

if("Unable to find the install" >< path)
  exit(0);

check_file = "Frontpg.exe";
if(!vers = fetch_file_version(sysPath:path, file_name:check_file))
  exit(0);

if(version_in_range(version:vers, test_version:"11.0", test_version2:"11.0.8338")) {
  report = report_fixed_ver(file_checked:path + "\" + check_file, installed_version:vers, vulnerable_range:"11.0 - 11.0.8338");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
