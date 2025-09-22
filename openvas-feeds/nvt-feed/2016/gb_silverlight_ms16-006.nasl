# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:silverlight";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806186");
  script_version("2024-07-03T06:48:05+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2016-0034");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-03 06:48:05 +0000 (Wed, 03 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-01 17:56:03 +0000 (Mon, 01 Jul 2024)");
  script_tag(name:"creation_date", value:"2016-01-13 08:51:19 +0530 (Wed, 13 Jan 2016)");
  script_name("Microsoft Silverlight Remote Code Execution Vulnerability (3126036)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_silverlight_detect.nasl");
  script_mandatory_keys("Microsoft/Silverlight/Installed");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3126036");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-006");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-006.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due when Microsoft
  Silverlight decodes strings using a malicious decoder that can return negative
  offsets that cause Silverlight to replace unsafe object headers with contents
  provided by an attacker.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code in the context of the vulnerable application. Failed
  exploit attempts will result in a denial-of-service condition.");

  script_tag(name:"affected", value:"Microsoft Silverlight version 5.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!msl_ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(msl_ver=~ "^5\.")
{
  if(version_in_range(version:msl_ver, test_version:"5.0", test_version2:"5.1.41211.0"))
  {
    report = 'Silverlight version: ' + msl_ver  + '\n' +
             'Vulnerable range:    5.0 - 5.1.41211.0';
    security_message(data:report);
    exit(0);
  }
}
