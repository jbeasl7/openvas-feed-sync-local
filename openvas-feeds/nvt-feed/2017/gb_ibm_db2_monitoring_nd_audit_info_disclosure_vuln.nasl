# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:db2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809855");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2014-0919");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-01-04 11:08:09 +0530 (Wed, 04 Jan 2017)");

  script_name("IBM Db2 'monitoring' and 'audit feature' Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"IBM Db2 is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to IBM Db2 stores passwords during the processing of
  certain SQL statements by the monitoring and audit facilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote authenticated users to obtain
  sensitive information via commands associated with these facilities.");

  script_tag(name:"affected", value:"IBM Db2 versions 9.5 through FP10, IBM Db2 versions 9.7 through FP10,
  IBM Db2 versions 9.8 through FP5, IBM Db2 versions 10.1 through FP4 and IBM Db2 versions 10.5 through FP5");

  script_tag(name:"solution", value:"Apply the appropriate fix");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1032247");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74217");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1032247");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21698021");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl");
  script_mandatory_keys("ibm/db2/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "9.5.0", test_version2: "9.5.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.0.11");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.7.0", test_version2: "9.7.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.7.0.11");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.8.0", test_version2: "9.8.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.8.0.6");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.1.0", test_version2: "10.1.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.0.5");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.5.0", test_version2: "10.5.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.5.0.6");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
