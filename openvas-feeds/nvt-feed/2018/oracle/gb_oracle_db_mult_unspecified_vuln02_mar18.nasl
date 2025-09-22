# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:database_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812796");
  script_version("2024-10-29T05:05:46+0000");
  script_cve_id("CVE-2011-0870", "CVE-2011-0848", "CVE-2011-0831", "CVE-2011-0816",
                "CVE-2011-0876", "CVE-2011-0879", "CVE-2011-2244", "CVE-2011-2257");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-10-29 05:05:46 +0000 (Tue, 29 Oct 2024)");
  script_tag(name:"creation_date", value:"2018-03-07 15:14:30 +0530 (Wed, 07 Mar 2018)");
  script_name("Oracle Database Server Multiple Unspecified Vulnerabilities-02 (Mar 2018)");

  script_tag(name:"summary", value:"Oracle Database Server is prone to multiple unspecified security vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple unspecified
  errors in components 'Instance Management', 'Enterprise Manager Console',
  'Enterprise Config Management', 'CMDB Metadata & Instance APIs', 'Security
  Framework', 'Schema Management' and 'Database Target Type Menus'.");

  script_tag(name:"impact", value:"Successfully exploitation will allow remote
  attackers to affect confidentiality, integrity, and availability via unknown
  vectors.");

  script_tag(name:"affected", value:"Oracle Database Server versions
  10.1.0.5, 10.2.0.3, 10.2.0.4, 10.2.0.5, 11.1.0.7, 11.2.0.1, and 11.2.0.2");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://www.oracle.com/technetwork/topics/security/cpujuly2011-313328.html");
  script_copyright("Copyright (C) 2018 Greenbone AG");
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

affected = make_list('10.1.0.5', '10.2.0.3', '10.2.0.4', '10.2.0.5', '11.1.0.7', '11.2.0.1', '11.2.0.2');
foreach version (affected) {
  if(ver == version) {
    report = report_fixed_ver(installed_version:ver, fixed_version: "Apply the patch", install_path:path);
    security_message(port:port, data:report);
    exit(0);
  }
}
exit(0);
