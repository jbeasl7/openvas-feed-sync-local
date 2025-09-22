# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:db2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801588");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-02-07 15:21:16 +0100 (Mon, 07 Feb 2011)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_cve_id("CVE-2011-0757");

  script_name("IBM Db2 DBADM Privilege Revocation Security Bypass Vulnerability");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl");
  script_mandatory_keys("ibm/db2/detected");

  script_tag(name:"impact", value:"Successful exploitation allows remote authenticated users to
  execute non-DDL statements by leveraging previous possession of this authority.");

  script_tag(name:"affected", value:"IBM Db2 version 9.1 before FP10, version 9.5 before FP6a and version 9.7
  before FP2.");

  script_tag(name:"insight", value:"The flaw is due to an error in the application while revoking
  'DBADM' privileges. This does not restrict users from executing non-DDL statements.");

  script_tag(name:"solution", value:"Upgrade to IBM Db2 version 9.1 FP10, 9.5 FP6a, 9.7 FP2 or later.");

  script_tag(name:"summary", value:"IBM Db2 is prone to a security bypass vulnerability.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/43148");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46064");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/65008");
  script_xref(name:"URL", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21426108");
  script_xref(name:"URL", value:"https://www-304.ibm.com/support/docview.wss?uid=swg1IC66814");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=71&uid=swg27007053");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "9.7.0", test_version2: "9.7.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.7.0.2");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.5.0", test_version2: "9.5.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.0.6");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.1.0", test_version2: "9.1.0.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1.0.10");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
