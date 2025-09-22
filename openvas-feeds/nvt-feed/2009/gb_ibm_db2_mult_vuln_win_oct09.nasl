# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801009");
  script_version("2024-02-08T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-10-06 07:21:15 +0200 (Tue, 06 Oct 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2009-3471", "CVE-2009-3472");

  script_name("IBM Db2 Multiple Vulnerabilities (Oct 2009) - Windows");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("ibm/db2/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/36890");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36540");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21403619");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21386689");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=71&uid=swg27007053");

  script_tag(name:"affected", value:"IBM Db2 version 8 prior to Fixpack 18, 9.1 prior to Fixpack 8 and
  9.5 prior to Fixpack 4.");

  script_tag(name:"insight", value:"- An unspecified error exists related to a table function when the definer
  loses required privileges.

  - An unspecified error can be exploited to insert, update, or delete rows in
  a table without having required privileges.");

  script_tag(name:"solution", value:"Update Db2 8 Fixpack 18, 9.1 Fixpack 8, 9.5 Fixpack 4 or later.");

  script_tag(name:"summary", value:"IBM Db2 is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:ibm:db2";

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "8.0.0", test_version2: "8.1.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.18");
  security_message(data: report, port: 0);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.1.0.0", test_version2: "9.1.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1.0.8");
  security_message(data: report, port: 0);
  exit(0);
}

if (version_in_range(version: version, test_version: "9.5.0.0", test_version2: "9.5.302.513")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.400.576");
  security_message(data: report, port: 0);
  exit(0);
}

exit(99);
