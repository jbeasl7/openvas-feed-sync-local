# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:silverlight";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807374");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2016-3209");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:11:00 +0000 (Fri, 12 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-10-12 12:07:00 +0530 (Wed, 12 Oct 2016)");
  script_name("Microsoft Silverlight Information Disclosure Vulnerability (3192884) - Mac OS X");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-120.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due when Microsoft
  Silverlight improperly handles the true type font parsing.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker to
  disclosure information of a targeted system.");

  script_tag(name:"affected", value:"Microsoft Silverlight version 5 on Mac OS X.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3193713");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93385");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-120");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_ms_silverlight_detect_macosx.nasl");
  script_mandatory_keys("MS/Silverlight/MacOSX/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

msl_ver = "";

if(!msl_ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(msl_ver=~ "^5\.")
{
  if(version_is_less(version:msl_ver, test_version:"5.1.50901.0"))
  {
    report = 'Silverlight version:  ' + msl_ver  + '\n' +
             'Vulnerable range:  5.0 - 5.1.50900.0' + '\n' ;
    security_message(data:report);
    exit(0);
  }
}
