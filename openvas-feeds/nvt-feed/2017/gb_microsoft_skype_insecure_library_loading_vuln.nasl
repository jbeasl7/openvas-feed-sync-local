# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:skype:skype";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810905");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-6517");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-04-05 16:33:26 +0530 (Wed, 05 Apr 2017)");
  script_name("Microsoft Skype Insecure Library Loading Vulnerability");

  script_tag(name:"summary", value:"Microsoft Skype is prone to insecure library loading vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the way '.dll'
  files are loaded by Skype. The specific flaw exists within the handling of DLL
  (api-ms-win-core-winrt-string-l1-1-0.dll) loading by the Skype.exe process.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to execute arbitrary code on the target system
  without the user's knowledge.");

  script_tag(name:"affected", value:"Microsoft Skype version 7.16.0.102.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Mar/44");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96969");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_skype_detect_win.nasl");
  script_mandatory_keys("Skype/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!skypeVer = get_app_version(cpe:CPE)){
   exit(0);
}

if(version_is_equal(version:skypeVer, test_version:"7.16.0.102"))
{
  report = report_fixed_ver(installed_version:skypeVer, fixed_version:"None");
  security_message(data:report);
  exit(0);
}

exit(0);
