# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ocsinventory-ng:ocs_inventory_ng";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801204");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-05-05 15:59:12 +0200 (Wed, 05 May 2010)");
  script_cve_id("CVE-2010-1594", "CVE-2010-1595");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("OCS Inventory NG Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_ocs_inventory_ng_detect.nasl");
  script_mandatory_keys("ocs_inventory_ng/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/38311");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38131");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1001-exploits/ocsinventoryng-sqlxss.txt");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to inject arbitrary web script
  or HTML and conduct Cross-Site Scripting attacks.");

  script_tag(name:"affected", value:"OCS Inventory NG 1.02.1 and prior.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - improper validation of user-supplied input via 1)the query string, (2)the BASE parameter, or (3)the ega_1 parameter
  in ocsreports/index.php that allow remote attackers to inject arbitrary web script or HTML.

  - improper validation of user-supplied input via (1)c, (2)val_1, or (3)onglet_bis parameter in ocsreports/index.php
  that allow remote attackers to execute arbitrary SQL commands.");

  script_tag(name:"solution", value:"Upgrade to the latest version of OCS Inventory NG 1.02.3 or later.");

  script_tag(name:"summary", value:"OCS Inventory NG is prone to multiple cross-site scripting and SQL injection vulnerabilities.");

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
