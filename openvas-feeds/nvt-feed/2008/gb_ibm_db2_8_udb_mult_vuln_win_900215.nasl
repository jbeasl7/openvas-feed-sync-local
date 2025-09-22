# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900215");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-09-25 09:10:39 +0200 (Thu, 25 Sep 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-2154", "CVE-2008-3958", "CVE-2008-3960");

  script_name("IBM Db2 Universal Database Multiple Vulnerabilities (Sep 2008) - Windows");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("ibm/db2/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"ftp://ftp.software.ibm.com/ps/products/db2/fixes/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31058");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/2517");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2008/Sep/1020826.html");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1JR29274");

  script_tag(name:"summary", value:"IBM Db2 is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The flaws exist due to unspecified errors in processing of

  - CONNECT/ATTACH requests

  - DB2FMP process and DB2JDS service");

  script_tag(name:"affected", value:"IBM DB2 version 8 prior to Fixpak 17 on Windows (All).");

  script_tag(name:"solution", value:"Update to version 8 Fixpak 17 or later.");

  script_tag(name:"impact", value:"Remote exploitation could allow attackers to bypass security
  restrictions, cause a denial of service or gain elevated privileges.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

CPE = "cpe:/a:ibm:db2";

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range(version: version, test_version: "8.0.0", test_version2: "8.2.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.2.17");
  security_message(data: report, port: 0);
  exit(0);
}

exit(99);
