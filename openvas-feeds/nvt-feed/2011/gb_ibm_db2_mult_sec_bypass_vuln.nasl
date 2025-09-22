# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:db2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801930");
  script_version("2024-02-21T05:06:27+0000");
  script_tag(name:"last_modification", value:"2024-02-21 05:06:27 +0000 (Wed, 21 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-05-16 15:25:30 +0200 (Mon, 16 May 2011)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2011-1846", "CVE-2011-1847");

  script_name("IBM Db2 Multiple Security Bypass Vulnerabilities (May 2011)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl");
  script_mandatory_keys("ibm/db2/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass security restrictions,
  gain knowledge of sensitive information or cause a denial of service.");

  script_tag(name:"affected", value:"IBM Db2 versions prior to 9.5 Fix Pack 7 and prior to 9.7 Fix Pack 4");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An access validation error which could allow users to update statistics for tables without appropriate privileges.

  - An error when revoking role memberships, which could result in a user continuing to have privileges to execute
    a non-DDL statement after role membership has been revoked from its group.");

  script_tag(name:"solution", value:"Update Db2 to 9.5 Fix Pack 7, 9.7 Fix Pack 4, or later.");

  script_tag(name:"summary", value:"IBM Db2 is prone to multiple security bypass vulnerabilities.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/44229");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47525");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/66980");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/1083");
  script_xref(name:"URL", value:"https://www-304.ibm.com/support/docview.wss?uid=swg1IC71263&crawler=1");
  script_xref(name:"URL", value:"http://www.ibm.com/support/docview.wss?rs=71&uid=swg27007053");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "9.7.0", test_version2: "9.7.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.7.0.4");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.5.0", test_version2: "9.5.0.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.0.7");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
