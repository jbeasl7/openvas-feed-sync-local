# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809096");
  script_version("2024-06-21T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-06-21 05:05:42 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"creation_date", value:"2016-11-14 15:30:37 +0530 (Mon, 14 Nov 2016)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:14:00 +0000 (Fri, 12 Oct 2018)");

  script_cve_id("CVE-2016-7249", "CVE-2016-7250", "CVE-2016-7251", "CVE-2016-7252",
                "CVE-2016-7253", "CVE-2016-7254");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Microsoft SQL Server Multiple Vulnerabilities (MS16-136)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_sql_server_consolidation.nasl");
  script_mandatory_keys("microsoft/sqlserver/tcp_listener/detected");

  script_tag(name:"summary", value:"Microsoft SQL Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2016-7249, CVE-2016-7250, CVE-2016-7252, CVE-2016-7253, CVE-2016-7254: Privilege escalation

  - CVE-2016-7251: Cross-site scripting (XSS)");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain
  elevated privileges that could be used to view, change, or delete data, or create new accounts,
  also can gain additional database and file information and to spoof content, disclose
  information, or take any action that the user could take on the site on behalf of the targeted
  user.");

  script_tag(name:"affected", value:"- Microsoft SQL Server 2012 x86/x64 Edition Service Pack 2 and prior

  - Microsoft SQL Server 2012 x86/x64 Edition Service Pack 3 and prior

  - Microsoft SQL Server 2014 x86/x64 Edition Service Pack 1 and prior

  - Microsoft SQL Server 2014 x86/x64 Edition Service Pack 2 and prior

  - Microsoft SQL Server 2016 x64 Edition");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-136");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94037");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94060");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94043");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94050");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94061");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94056");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

CPE = "cpe:/a:microsoft:sql_server";

if (!port = get_app_port(cpe:CPE, service:"tcp_listener"))
  exit(0);

if (!infos = get_app_full(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

if (!vers = infos["internal_version"])
  exit(0);

## MS SQL 2012 SP2 : GDR x64/x86 ==> 11.0.5388.0  ; CU x64/x86 ==> 11.0.5676.0
if (vers =~ "^11\.0") {
  if (version_in_range(version:vers, test_version:"11.0.5400.0", test_version2:"11.0.5675.0")) {
    VULN = TRUE;
    vulnerable_range = "11.0.5400.0 - 11.0.5675.0";
  }
  else if (version_in_range(version:vers, test_version:"11.0.5058.0", test_version2:"11.0.5387.0")) {
    VULN = TRUE;
    vulnerable_range = "11.0.5000.0 - 11.0.5387.0";
  }
}

## MS SQL 2012 SP3 : GDR x64/x86 ==> 11.0.6248.0   ; CU x64/x86 ==> 11.0.6567.0
else if (vers =~ "^11\.0") {
  if (version_in_range(version:vers, test_version:"11.0.6000.0", test_version2:"11.0.6247.0")) {
    VULN = TRUE;
    vulnerable_range = "11.0.6000.0 - 11.0.6247.0";
  }
  else if (version_in_range(version:vers, test_version:"11.0.6400.0", test_version2:"11.0.6566.0")) {
    VULN = TRUE;
    vulnerable_range = "11.0.6400.0 - 11.0.6566.0";
  }
}

## MS SQL 2014 SP1 : GDR x64/x86 ==> 12.0.4487.0   ; CU x64/x86 ==> 12.0.4232.0
else if (vers =~ "^12\.0") {
  if (version_in_range(version:vers, test_version:"12.0.4000.0", test_version2:"12.0.4231.0")) {
    VULN = TRUE;
    vulnerable_range = "12.0.4000.0 - 12.0.4231.0";
  }
  else if (version_in_range(version:vers, test_version:"12.0.4300.0", test_version2:"12.0.4486.0")) {
    VULN = TRUE;
    vulnerable_range = "12.0.4300.0 - 12.0.4486.0";
  }
}

## MS SQL 2014 SP2 : GDR x64/x86 ==> 12.0.5203.0   ; CU x64/x86 ==> 12.0.5532.0
else if (vers =~ "^12\.0") {
  if (version_in_range(version:vers, test_version:"12.0.5000.0", test_version2:"12.0.5202.0")) {
    VULN = TRUE;
    vulnerable_range = "12.0.5000.0 - 12.0.5202.0";
  }
  else if (version_in_range(version:vers, test_version:"12.0.5400.0", test_version2:"12.0.5531.0")) {
    VULN = TRUE;
    vulnerable_range = "12.0.5400.0 - 12.0.5531.0";
  }
}

## MS SQL 2016 : GDR x64/x86 ==> 13.0.1722.0 ; CU x64/x86 ==> 13.0.2185.3
else if (vers =~ "^13\.0") {
  if(version_in_range(version:vers, test_version:"13.0.1000.0", test_version2:"13.0.1721.0")) {
    VULN = TRUE;
    vulnerable_range = "13.0.1000.0 - 13.0.1721.0";
  }
  else if (version_in_range(version:vers, test_version:"13.0.2000.0", test_version2:"13.0.2185.2")) {
    VULN = TRUE;
    vulnerable_range = "13.0.2000.0 - 13.0.2185.2";
  }
}

if (VULN) {
  report = report_fixed_ver(installed_version:vers,
                            vulnerable_range:vulnerable_range);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
