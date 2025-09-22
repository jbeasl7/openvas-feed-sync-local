# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ocsinventory-ng:ocs_inventory_ng";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902059");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-06-01 15:40:11 +0200 (Tue, 01 Jun 2010)");
  script_cve_id("CVE-2010-1733");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("OCS Inventory NG Multiple SQL Injection Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_ocs_inventory_ng_detect.nasl");
  script_mandatory_keys("ocs_inventory_ng/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/38311");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/55873");

  script_tag(name:"insight", value:"The flaws are due to the error in the 'index.php' page, which fails to
  properly verify the user supplied input via the 'search' form for the various
  inventory fields and via the 'All softwares' search form for the 'Software name' field.");

  script_tag(name:"solution", value:"Upgrade to OCS Inventory NG version 1.02.3 or later.");

  script_tag(name:"summary", value:"OCS Inventory NG is prone to multiple SQL injection vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to view, add, modify
  or delete information in the back-end database.");

  script_tag(name:"affected", value:"OCS Inventory NG prior to 1.02.3.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if (version_is_less(version: vers, test_version: "1.02.3")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "1.02.3", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
