# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801977");
  script_version("2024-11-14T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-11-14 05:05:31 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"creation_date", value:"2011-09-09 17:36:48 +0200 (Fri, 09 Sep 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2011-1359");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere Application Server Directory Traversal Vulnerability (Sep 2011)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_consolidation.nasl");
  script_mandatory_keys("ibm/websphere/detected");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to a directory
  traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to error in administration console which fails
  to handle certain requests. This allows remote attackers to read arbitrary files via a '../'
  (dot dot) in the URI.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to read arbitrary
  files on the affected application and obtain sensitive information that may lead to further
  attacks.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server version 6.1.x prior to
  6.1.0.41, 7.0.x prior to 7.0.0.19 and 8.0.x prior to 8.0.0.1.");

  script_tag(name:"solution", value:"Update to version 6.1.0.41, 7.0.0.19, 8.0.0.1 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/45749");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49362");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/69473");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21509257");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24028875");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "6.1", test_version_up: "6.1.0.41")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.0.41");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0", test_version_up: "7.0.0.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.0.19");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.0", test_version_up: "8.0.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.0.1");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
