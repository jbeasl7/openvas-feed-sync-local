# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:silverlight";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805554");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-1715");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-05-13 12:50:27 +0530 (Wed, 13 May 2015)");
  script_name("Microsoft Silverlight Elevation of Privilege Vulnerability (3058985)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-049.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as the Silverlight improperly
  allows applications that are intended to run at a low integrity level (very
  limited permissions) to be executed at a medium integrity level (permissions of
  the current user) or higher.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code with the same or higher level of permissions as the
  currently logged on user.");

  script_tag(name:"affected", value:"Microsoft Silverlight version 5.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3058985");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74503");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-049");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_silverlight_detect.nasl");
  script_mandatory_keys("Microsoft/Silverlight/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!msl_ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(msl_ver=~ "^5\.")
{
  if(version_in_range(version:msl_ver, test_version:"5.0", test_version2:"5.1.40415"))
  {
    report = 'Silverlight version:  ' + msl_ver  + '\n' +
             'Vulnerable range:  5.0 - 5.1.40415' + '\n' ;
    security_message(data:report);
    exit(0);
  }
}
