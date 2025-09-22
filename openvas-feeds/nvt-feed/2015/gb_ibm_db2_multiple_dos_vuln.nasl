# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:db2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805035");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-01-08 13:04:41 +0530 (Thu, 08 Jan 2015)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2014-6209", "CVE-2014-8901");

  script_name("IBM Db2 Multiple Denial of Service Vulnerabilities");

  script_tag(name:"summary", value:"IBM Db2 is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws are due to

  - An error during the handling of a specially crafted ALTER TABLE statement on an identity column.

  - An error when handling a specially crafted XML query, which can result in a consumption of CPU resources.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to cause the server to terminate abnormally and cause a denial of service.");

  script_tag(name:"affected", value:"IBM Db2 versions 9.5 through FP10, 9.7 through FP10, 9.8 through FP5,
  10.1 through FP4 and 10.5 through FP4.");

  script_tag(name:"solution", value:"Apply the appropriate fix from the referenced advisory.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/99110");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/98684");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21690787");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21692358");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl");
  script_mandatory_keys("ibm/db2/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "9.5.0.0", test_version2: "9.5.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.7.0.0", test_version2: "9.7.0.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.8.0.0", test_version2: "9.8.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}


if (version_in_range(version: version, test_version: "10.1.0", test_version2: "10.1.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "10.5.0", test_version2: "10.5.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
