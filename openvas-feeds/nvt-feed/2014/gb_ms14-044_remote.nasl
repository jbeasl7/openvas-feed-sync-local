# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805110");
  script_version("2024-06-21T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-06-21 05:05:42 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"creation_date", value:"2014-12-01 16:03:48 +0530 (Mon, 01 Dec 2014)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_cve_id("CVE-2014-1820", "CVE-2014-4061");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Microsoft SQL Server Multiple Vulnerabilities (MS14-044)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_sql_server_consolidation.nasl");
  script_mandatory_keys("microsoft/sqlserver/tcp_listener/detected");

  script_tag(name:"summary", value:"Microsoft SQL Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2014-1820: Cross-site scripting (XSS) in Master Data Services (MDS)

  - CVE-2014-4061: Denial of service (DoS) when processing T-SQL batch commands");

  script_tag(name:"affected", value:"- Microsoft SQL Server 2014 x64

  - Microsoft SQL Server 2012 x86/x64 Service Pack 1 and prior

  - Microsoft SQL Server 2008 R2 x86/x64 Service Pack 2 and prior

  - Microsoft SQL Server 2008 x86/x64 Service Pack 3 and prior");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS14-044");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69071");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69088");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

CPE = "cpe:/a:microsoft:sql_server";

if (!port = get_app_port(cpe:CPE, service:"tcp_listener"))
  exit(0);

if (!infos = get_app_full( cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

if (!vers = infos["internal_version"])
  exit(0);

## MS SQL 2014 : GDR x64 ==> 12.0.2254.0  ; QFE x64 ==> 12.0.2381.0
if (vers =~ "^12\.0") {
  if (version_in_range(version:vers, test_version:"12.0.2000", test_version2:"12.0.2253") ||
      version_in_range(version:vers, test_version:"12.0.2300", test_version2:"12.0.2380")) {
    report = report_fixed_ver(installed_version:vers,
                              vulnerable_range:"12.0.2000 - 12.0.2253 / 12.0.2300 - 12.0.2380");
    security_message(port:port, data:report);
    exit(0);
  }
}

## MS SQL 2012 SP1 : GDR x64/x86 ==> 11.0.3153.0  ; QFE x64/x86 ==> 11.0.3460.0
if (vers =~ "^11\.0") {
  if (version_in_range(version:vers, test_version:"11.0.3000", test_version2:"11.0.3152") ||
      version_in_range(version:vers, test_version:"11.0.3300", test_version2:"11.0.3459")) {
    report = report_fixed_ver(installed_version:vers,
                              vulnerable_range:"11.0.3000 - 11.0.3152 / 11.0.3300 - 11.0.3459");
    security_message(port:port, data:report);
    exit(0);
  }
}

## MS SQL 2008 R2 SP2 : GDR x64/x86 ==> 10.50.4033.0 ; QFE x64/x86 ==> 10.50.4321.0
if (vers =~ "^10\.50") {
  if (version_in_range(version:vers, test_version:"10.50.4000", test_version2:"10.50.4032") ||
      version_in_range(version:vers, test_version:"10.50.4251", test_version2:"10.50.4320")) {
    report = report_fixed_ver(installed_version:vers,
                              vulnerable_range:"10.50.4000 - 10.50.4032 / 10.50.4251 - 10.50.4320");
    security_message(port:port, data:report);
    exit(0);
  }
}

## MS SQL 2008 SP3 : GDR x64/x86 ==> 10.0.5520.0  ; QFE x64/x86 ==> 10.0.5869.0
if (vers =~ "^10\.0") {
  if (version_in_range(version:vers, test_version:"10.0.5500", test_version2:"10.0.5519") ||
      version_in_range(version:vers, test_version:"10.0.5750", test_version2:"10.0.5868")) {
    report = report_fixed_ver(installed_version:vers,
                              vulnerable_range:"10.0.5500 - 10.0.5519 / 10.0.5750 - 10.0.5868");
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
