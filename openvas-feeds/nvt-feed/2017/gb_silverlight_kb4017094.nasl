# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:silverlight";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810742");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2013-6629");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-04-12 14:56:42 +0530 (Wed, 12 Apr 2017)");
  script_name("Microsoft Silverlight Information Disclosure Vulnerability (KB4017094)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_silverlight_detect.nasl");
  script_mandatory_keys("Microsoft/Silverlight/Installed");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4017094");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63676");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft security update KB4017094.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists within the open-source
  libjpeg image-processing library where it fails to properly handle objects
  in memory.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to cause information to be disclosed that could allow for bypassing the
  ASLR security feature that protects users from a broad class of
  vulnerabilities.");

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
  if(version_is_less(version:msl_ver, test_version:"5.1.50906.0"))
  {
    report = 'Silverlight version: ' + msl_ver  + '\n' +
             'Vulnerable range:    5.0 - 5.1.50905.0';
    security_message(port:0, data:report);
    exit(0);
  }
}
