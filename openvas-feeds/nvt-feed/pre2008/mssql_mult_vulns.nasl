# SPDX-FileCopyrightText: 2006 John Lampe
# SPDX-FileCopyrightText: New code since 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# Supersedes MS02-034 MS02-020 MS02-007 MS01-060 MS01-032 MS00-092 MS00-048
#            MS00-041 MS00-014 MS01-041
#
# CAN-2002-0056, CAN-2002-0154, CAN-2002-0624,
# CAN-2002-0641, CAN-2002-0642  CVE-2001-0879
# CVE-2000-0603  CAN-2000-1082  CAN-2000-1083
# CAN-2000-1084  CAN-2000-1085  CAN-2001-0509
# CAN-2000-1086

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11217");
  script_version("2024-07-11T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-07-11 05:05:33 +0000 (Thu, 11 Jul 2024)");
  script_tag(name:"creation_date", value:"2006-03-26 18:10:09 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2000-0202", "CVE-2000-0485", "CVE-2000-0603", "CVE-2000-1081",
                "CVE-2000-1082", "CVE-2000-1083", "CVE-2000-1084", "CVE-2000-1085",
                "CVE-2000-1086", "CVE-2000-1087", "CVE-2000-1088", "CVE-2001-0344",
                "CVE-2001-0509", "CVE-2001-0542", "CVE-2001-0879", "CVE-2002-0056",
                "CVE-2002-0154", "CVE-2002-0624", "CVE-2002-0641", "CVE-2002-0642",
                "CVE-2002-0982");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Microsoft SQL (MSSQL) Server 6, 7, 2000 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2006 John Lampe");
  script_family("Databases");
  script_dependencies("gb_microsoft_sql_server_consolidation.nasl");
  script_mandatory_keys("microsoft/sqlserver/smb-login/detected");

  script_tag(name:"summary", value:"The plugin attempts a smb connection to read version from the
  registry key 'SOFTWARE\Microsoft\MSSQLServer\MSSQLServer\CurrentVersion' to determine the version
  of Microsoft SQL and the Service Pack the host is running.");

  script_tag(name:"solution", value:"Apply current service packs and hotfixes.");

  script_tag(name:"impact", value:"Some versions may allow remote access, denial of service attacks,
  and the ability of a hacker to run code of their choice.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210228153234/http://www.securityfocus.com/bid/1292");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210228153234/http://www.securityfocus.com/bid/2030");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210228153234/http://www.securityfocus.com/bid/2042");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210228153234/http://www.securityfocus.com/bid/2043");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210228153234/http://www.securityfocus.com/bid/2863");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210228153234/http://www.securityfocus.com/bid/3733");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210228153234/http://www.securityfocus.com/bid/4135");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210228153234/http://www.securityfocus.com/bid/4847");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210228153234/http://www.securityfocus.com/bid/5014");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210228153234/http://www.securityfocus.com/bid/5205");
  script_xref(name:"IAVA", value:"2002-B-0004");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

CPE = "cpe:/a:microsoft:sql_server";

if(isnull(port = get_app_port(cpe:CPE, service:"smb-login")))
  exit(0);

if(!infos = get_app_full(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

if(!vers = infos["internal_version"])
  exit(0);

location = infos["location"];

if(version_in_range_exclusive(version:vers, test_version_lo:"6.00.121", test_version_up:"7.00.1077")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.00.1077", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

if(version_in_range_exclusive(version:vers, test_version_lo:"8.00.047", test_version_up:"8.00.760")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"8.00.760", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
