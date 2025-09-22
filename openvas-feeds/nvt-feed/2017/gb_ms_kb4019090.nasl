# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811287");
  script_version("2024-06-21T05:05:42+0000");
  script_cve_id("CVE-2017-8516");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-06-21 05:05:42 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-27 01:04:00 +0000 (Thu, 27 Oct 2022)");
  script_tag(name:"creation_date", value:"2017-08-09 15:26:44 +0530 (Wed, 09 Aug 2017)");
  script_name("Microsoft SQL Server 2012 Service Pack 3 Information Disclosure Vulnerability (KB4019090)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4019090.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in Microsoft
  SQL Server Analysis Services when it improperly enforces permissions.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to gain access to sensitive information and access to an affected SQL server
  database.");

  script_tag(name:"affected", value:"Microsoft SQL Server 2012 x64/x86 Service Pack 3 (CU).");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4019090");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100041");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");

  script_dependencies("gb_microsoft_sql_server_consolidation.nasl");
  script_mandatory_keys("microsoft/sqlserver/smb-login/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:microsoft:sql_server";

if(isnull(port = get_app_port(cpe:CPE, service:"smb-login")))
  exit(0);

if(!infos = get_app_full(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

if(!vers = infos["internal_version"])
  exit(0);

location = infos["location"];

## update for SQL Server 2012 Service Pack 3 CU
if(vers =~ "^11\.0") {
  if(version_in_range(version:vers, test_version:"11.0.6400.0", test_version2:"11.0.6607.2")) {
    report = report_fixed_ver(installed_version:vers, install_path:location,
                              vulnerable_range:"11.0.6400.0 - 11.0.6607.2");
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
