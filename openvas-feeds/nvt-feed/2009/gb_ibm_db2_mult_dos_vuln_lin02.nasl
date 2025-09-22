# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:db2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900679");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-06-30 16:55:49 +0200 (Tue, 30 Jun 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2008-6821", "CVE-2008-6820", "CVE-2008-2154");

  script_name("IBM Db2 Multiple Vulnerabilities - Linux");

  script_xref(name:"URL", value:"http://secunia.com/advisories/31787");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31058");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35409");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Jun/1022319.htm");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1JR30227");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=0&uid=swg24022678");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("ibm/db2/detected", "Host/runs_unixoide");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to bypass security restrictions,
  cause a denial of service or gain elevated privileges.");

  script_tag(name:"affected", value:"IBM Db2 version 8 prior to Fixpak 17, 9.1 prior to Fixpak 5 and
  9.5 prior to Fixpak 2.");

  script_tag(name:"insight", value:"The flaws are due to:

  - An unspecified error related to the DB2FMP process running with OS privileges.

  - An error in INSTALL_JAR procedure might allow remote authenticated users to create or overwrite arbitrary
    files via unspecified calls.

  - A boundary error in DAS server code can be exploited to cause a buffer overflow via unspecified vectors.");

  script_tag(name:"solution", value:"Update Db2 8 Fixpak 17, 9.1 Fixpak 5, 9.5 Fixpak 2 or later.");

  script_tag(name:"summary", value:"IBM Db2 is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "8.0.0", test_version2: "8.1.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.17");
  security_message(data: report, port: 0);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.1.0.0", test_version2: "9.1.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1.0.5");
  security_message(data: report, port: 0);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.5.0.0", test_version2: "9.5.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.0.2");
  security_message(data: report, port: 0);
}

exit(99);
