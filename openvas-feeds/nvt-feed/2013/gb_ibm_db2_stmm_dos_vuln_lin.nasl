# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:db2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803766");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-09-30 17:51:03 +0530 (Mon, 30 Sep 2013)");
  script_tag(name:"cvss_base", value:"1.5");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2011-1373");

  script_name("IBM Db2 STMM Denial Of Service Vulnerability - Linux");

  script_tag(name:"summary", value:"IBM DB2 is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Upgrade to IBM Db2 9.7 FP5 or later.");

  script_tag(name:"insight", value:"The flaw is due an error when the Self Tuning Memory Manager (STMM) feature
  and the AUTOMATIC DATABASE_MEMORY setting are configured.");

  script_tag(name:"affected", value:"IBM Db2 version 9.7 before FP5 on Linux.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to allows local users to cause a
  denial of service (daemon crash) via unknown vectors.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71043");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50686");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC70473");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("ibm/db2/detected", "Host/runs_unixoide");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "9.7.0.0", test_version2: "9.7.0.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.7.0.5");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
