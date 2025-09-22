# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only
CPE = "cpe:/a:oracle:database_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813691");
  script_version("2024-10-29T05:05:46+0000");
  script_cve_id("CVE-2017-15095");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-10-29 05:05:46 +0000 (Tue, 29 Oct 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-22 21:41:00 +0000 (Mon, 22 Feb 2021)");
  script_tag(name:"creation_date", value:"2018-07-18 12:59:43 +0530 (Wed, 18 Jul 2018)");
  script_name("Oracle Database Server 'Oracle Spatial' Component Unspecified Vulnerability");

  script_tag(name:"summary", value:"Oracle Database Server is prone to an unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified error in
  component 'Oracle Spatial'.");

  script_tag(name:"impact", value:"Successfully exploitation will allow remote
  attackers to affect confidentiality, availability and integrity via unknown
  vectors.");

  script_tag(name:"affected", value:"Oracle Database Server versions 12.2.0.1
  and 18.1");

  script_tag(name:"solution", value:"Apply appropriate patch provided by the vendor. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujul2018-4258247.html#AppendixDB");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/database/in-memory/downloads/index.html");
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

if(ver == "12.2.0.1" || ver == "18.1") {
  report = report_fixed_ver(installed_version:ver, fixed_version: "Apply the patch", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}
exit(0);
