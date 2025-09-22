# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811289");
  script_version("2024-06-21T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-06-21 05:05:42 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"creation_date", value:"2017-08-09 15:12:43 +0530 (Wed, 09 Aug 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-27 01:04:00 +0000 (Thu, 27 Oct 2022)");

  script_cve_id("CVE-2017-8516");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Microsoft SQL Server 2014 Information Disclosure Vulnerability (KB4019093)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_sql_server_consolidation.nasl");
  script_mandatory_keys("microsoft/sqlserver/tcp_listener/detected");

  script_tag(name:"summary", value:"Microsoft SQL Server is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Microsoft SQL Server Analysis Services improperly enforces
  permissions.");

  script_tag(name:"affected", value:"Microsoft SQL Server 2014 Service Pack 2 x86/x64 based Systems.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4019093");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100041");

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

if (version_in_range(version:vers, test_version:"12.0.5000.0", test_version2:"12.0.5206.0")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"12.0.5000.0 - 12.0.5206.0");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
