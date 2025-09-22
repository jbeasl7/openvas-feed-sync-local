# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE= "cpe:/a:symantec:endpoint_encryption";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808071");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2015-6556");
  script_tag(name:"cvss_base", value:"2.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-06-07 13:17:49 +0530 (Tue, 07 Jun 2016)");
  script_name("Symantec Endpoint Encryption Client Memory Dump Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"Symantec Endpoint Encryption (SEE) is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an access to a memory
  dump of 'EACommunicatorSrv.exe' in the Framework Service.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated users to discover credentials by triggering a memory dump.");

  script_tag(name:"affected", value:"Symantec Endpoint Encryption (SEE) version
  prior to 11.1.0.");

  script_tag(name:"solution", value:"Update to Symantec Endpoint Encryption (SEE)
  version 11.1.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&amp;pvid=security_advisory&amp;year=&amp;suid=20151214_00");

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

if(version_is_less(version:seeVer, test_version:"11.1.0"))
{
  report = report_fixed_ver(installed_version:seeVer, fixed_version: "11.1.0");
  security_message(data:report);
  exit(0);
}
