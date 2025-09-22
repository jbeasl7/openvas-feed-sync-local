# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symantec:endpoint_protection";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806004");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2015-1492", "CVE-2015-1491", "CVE-2015-1490", "CVE-2015-1489",
                "CVE-2015-1488", "CVE-2015-1487", "CVE-2015-1486");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2015-08-14 12:49:14 +0530 (Fri, 14 Aug 2015)");
  script_name("Symantec Endpoint Protection Manager Multiple Vulnerabilities (Aug 2015)");

  script_tag(name:"summary", value:"Symantec Endpoint Protection Manager is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Untrusted search path vulnerability in the client in SEP.

  - SQL injection vulnerability in the management console in SEPM.

  - Directory traversal vulnerability in the management console in SEPM.

  - Some other vulnerabilities in SEPM.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  local and remote users to gain privileges and remote authenticated users to
  execute arbitrary commands, to read arbitrary files, to write to arbitrary
  files and to bypass authentication.");

  script_tag(name:"affected", value:"Symantec Endpoint Protection Manager
  versions 12.1 before 12.1-RU6-MP1.");

  script_tag(name:"solution", value:"Upgrade to Symantec Endpoint Protection
  Manager 12.1 RU6 MP1.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Aug/1");
  script_xref(name:"URL", value:"http://codewhitesec.blogspot.in/2015/07/symantec-endpoint-protection.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_symantec_prdts_detect.nasl");
  script_mandatory_keys("Symantec/Endpoint/Protection");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!sepVer = get_app_version(cpe:CPE)){
    exit(0);
}

##  Check for Symantec Endpoint Protection versions
##  Check for vulnerable versions less than 12.1 RU6 MP1 = 12.1.6306.6100
if(sepVer =~ "^12\.1")
{
  if(version_in_range(version:sepVer, test_version:"12.1", test_version2:"12.1.6306.6099"))
  {
    report = 'Installed version: ' + sepVer + '\n' +
             'Fixed version:     12.1.6306.6100 \n';
    security_message(data:report);
    exit(0);
  }
}
