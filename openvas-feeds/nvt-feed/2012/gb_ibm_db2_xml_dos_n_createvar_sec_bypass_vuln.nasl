# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:db2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802730");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-04-03 10:41:54 +0530 (Tue, 03 Apr 2012)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2012-0712", "CVE-2012-0709");

  script_name("IBM Db2 XML Feature DoS and CREATE VARIABLE Security Bypass Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/48279/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52326");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/73496");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21588098");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC81379");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl");
  script_mandatory_keys("ibm/db2/detected");

  script_tag(name:"impact", value:"Successful exploitation allows remote users to cause denial of service,
  disclose sensitive information and bypass security restrictions.");

  script_tag(name:"affected", value:"IBM DB2 version 9.5 before FP9 and IBM DB2 version 9.7 before FP5");

  script_tag(name:"insight", value:"The flaws are due to an:

  - Improper checks on variables, An attacker could exploit this vulnerability
    using a specially crafted SQL statement to bypass table restrictions and obtain sensitive information.

  - Error in the XML feature allows remote authenticated users to cause a
    denial of service by calling the XMLPARSE function with a crafted string expression.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"IBM Db2 is prone to a denial of service and security bypass vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "9.8.0.0", test_version2: "9.8.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.8.0.5");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.7.0.0", test_version2: "9.7.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.7.0.6");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.5.0.0", test_version2: "9.5.0.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.0.9");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
