# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oxid:eshop";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900933");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-09-11 18:01:06 +0200 (Fri, 11 Sep 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2009-3112");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("OXID eShop Community Edition 4.x < 4.1.0 Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_oxid_eshop_http_detect.nasl");
  script_mandatory_keys("oxid_eshop/detected");

  script_tag(name:"summary", value:"OXID eShop Community Edition is prone to a privilege escalation
  vulnerability.");

  script_tag(name:"insight", value:"User supplied data passed to an unspecified variable is not
  sanitised before processing.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to gain administrator privileges
  and access shop backend via specially crafted URLs.");

  script_tag(name:"affected", value:"OXID eShop Community Edition version 4.0 prior to 4.1.0.");

  script_tag(name:"solution", value:"Apply the patches or update to version 4.1.0 or later.");

  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/385006.php");
  script_xref(name:"URL", value:"http://www.oxidforge.org/wiki/Security_bulletins/2009-001");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version =~ "^4\.") {
  if (version_is_less(version: version,test_version:"4.1.0")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "4.1.0", install_path: location);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
