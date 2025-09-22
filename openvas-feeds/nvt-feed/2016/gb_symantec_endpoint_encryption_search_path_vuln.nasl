# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE= "cpe:/a:symantec:endpoint_encryption";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808070");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2015-8156");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-18 22:37:00 +0000 (Wed, 18 May 2016)");
  script_tag(name:"creation_date", value:"2016-06-07 13:01:24 +0530 (Tue, 07 Jun 2016)");
  script_name("Symantec Endpoint Encryption Unquoted Windows Search Path Vulnerability");

  script_tag(name:"summary", value:"Symantec Endpoint Encryption (SEE) is prone to unquoted windows search path vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an improper
  validation of an unquoted search path in EEDService.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  users to gain privileges and insert arbitrary code in the root path.");

  script_tag(name:"affected", value:"Symantec Endpoint Encryption (SEE) version
  11.x before 11.1.1.");

  script_tag(name:"solution", value:"Update to Symantec Endpoint Encryption (SEE)
  version 11.1.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&amp;pvid=security_advisory&amp;suid=20160506_00");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_symantec_endpoint_encryption_detect.nasl");
  script_mandatory_keys("Symantec/Endpoint/Encryption/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!seeVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:seeVer, test_version:"11.0", test_version2:"11.1.0"))
{
  report = report_fixed_ver(installed_version:seeVer, fixed_version: "11.1.1");
  security_message(data:report);
  exit(0);
}
