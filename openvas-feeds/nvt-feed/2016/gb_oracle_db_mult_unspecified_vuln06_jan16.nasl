# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:database_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807042");
  script_version("2024-10-29T05:05:45+0000");
  script_cve_id("CVE-2014-6577", "CVE-2015-4753", "CVE-2015-0455");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-10-29 05:05:45 +0000 (Tue, 29 Oct 2024)");
  script_tag(name:"creation_date", value:"2016-01-25 14:59:25 +0530 (Mon, 25 Jan 2016)");
  script_name("Oracle Database Server Multiple Unspecified Vulnerabilities -06 (Jan 2016)");

  script_tag(name:"summary", value:"Oracle Database Server is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An Unspecified vulnerability in the XML Developer's Kit for C component.

  - An Unspecified vulnerability in the RDBMS Support Tools component.

  - An Unspecified vulnerability in the XDB - XML Database component.");

  script_tag(name:"impact", value:"Successfully exploitation will allow remote
  authenticated and local attackers to affect confidentiality, integrity, and
  availability via unknown vectors.");

  script_tag(name:"affected", value:"Oracle Database Server versions
  11.2.0.3, 11.2.0.4, 12.1.0.1, and 12.1.0.2.");

  script_tag(name:"solution", value:"Apply the patche from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72139");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75839");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74076");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("gb_oracle_database_consolidation.nasl");
  script_mandatory_keys("oracle/database/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

ver = infos["version"];
path = infos["location"];

if(ver =~ "^(12|11)") {
  if(version_is_equal(version:ver, test_version:"12.1.0.1") ||
     version_is_equal(version:ver, test_version:"12.1.0.2") ||
     version_is_equal(version:ver, test_version:"11.2.0.3") ||
     version_is_equal(version:ver, test_version:"11.2.0.4")) {
    report = report_fixed_ver(installed_version:ver, fixed_version:"Apply the appropriate patch", install_path:path);
    security_message(data:report, port:port);
    exit(0);
  }
}
