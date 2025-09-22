# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815507");
  script_version("2024-06-21T05:05:42+0000");
  script_cve_id("CVE-2019-1068");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-06-21 05:05:42 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-07-10 12:42:11 +0530 (Wed, 10 Jul 2019)");
  script_name("Microsoft SQL Server Remote Code Execution Vulnerability (KB4505224)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4505224");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the
  Microsoft SQL Server Database Engine. It incorrectly handles processing
  of internal functions.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code within the context of the SQL Server Database
  Engine service account. Failed exploit attempts may result in a
  denial-of-service condition.");

  script_tag(name:"affected", value:"Microsoft SQL Server 2017 GDR.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4505224");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/108954");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
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

if(vers =~ "^14\.0") {
  if(version_in_range(version:vers, test_version:"14.0.1000.169", test_version2:"14.0.2027.1")) {
    report = report_fixed_ver(installed_version:vers, install_path:location,
                              vulnerable_range:"14.0.1000.169 - 14.0.2027.1");
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
