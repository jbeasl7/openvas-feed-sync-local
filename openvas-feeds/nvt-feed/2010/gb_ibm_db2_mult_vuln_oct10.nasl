# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:db2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801522");
  script_version("2024-02-21T05:06:27+0000");
  script_tag(name:"last_modification", value:"2024-02-21 05:06:27 +0000 (Wed, 21 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-10-08 08:29:14 +0200 (Fri, 08 Oct 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2010-3734", "CVE-2010-3731", "CVE-2010-3732", "CVE-2010-3733",
                "CVE-2010-3736", "CVE-2010-3735", "CVE-2010-3737", "CVE-2010-3738",
                "CVE-2010-3740", "CVE-2010-3739");

  script_name("IBM Db2 Multiple Vulnerabilities (Oct 2010)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/41686");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2544");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC62856");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ56428");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1JR34218");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl");
  script_mandatory_keys("ibm/db2/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass security restrictions,
  gain knowledge of sensitive information or cause a denial of service.");

  script_tag(name:"affected", value:"IBM Db2 versions 9.5 before Fix Pack 6a.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error in 'Install' component, which enforces an unintended limit on
    password length, which makes it easier for attackers to obtain access via
    a brute-force attack.

  - A buffer overflow in the 'Administration Server' component, which allows an
    attacker to cause a denial of service via unspecified vectors.

  - An error in 'DRDA Services' component, which allows remote authenticated
    users to cause a denial of service.

  - The 'Engine Utilities' component uses world-writable permissions for the
   'sqllib/cfg/db2sprf' file, which allows local users to gain privileges by
    modifying this file.

  - A memory leak in the 'Relational Data Services' component, when the
    connection concentrator is enabled.

  - The 'Query Compiler, Rewrite, Optimizer' component, allows remote
    authenticated users to cause a denial of service (CPU consumption).

  - The 'Security' component logs 'AUDIT' events by using a USERID and an
    AUTHID value corresponding to the instance owner, instead of a USERID and
    an AUTHID value corresponding to the logged-in user account.

  - The 'Net Search Extender' (NSE) implementation in the Text Search component
    does not properly handle an alphanumeric Fuzzy search.

  - The audit facility in the 'Security' component uses instance-level audit
    settings to capture connection (aka CONNECT and AUTHENTICATION) events in
    certain circumstances in which database-level audit settings were intended.");

  script_tag(name:"solution", value:"Update Db2 version 9.5 Fix Pack 6a.");

  script_tag(name:"summary", value:"IBM DB2 is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "9.5.0.0", test_version2: "9.5.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.0.6");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
