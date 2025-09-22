# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ocsinventory-ng:ocs_inventory_ng";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902749");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2011-4024");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-11-15 16:35:51 +0530 (Tue, 15 Nov 2011)");
  script_name("OCS Inventory NG Persistent Cross-site Scripting Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_ocs_inventory_ng_detect.nasl");
  script_mandatory_keys("ocs_inventory_ng/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/46311");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50011");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/70406");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18005/");

  script_tag(name:"insight", value:"The flaw exists due to certain system information passed via a 'POST' request
  to '/ocsinventory' is not properly sanitised before being used.");

  script_tag(name:"solution", value:"Upgrade to OCS Inventory NG version 2.0.2 or later.");

  script_tag(name:"summary", value:"OCS Inventory NG is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in
  context of an affected site when the malicious data is being viewed.");

  script_tag(name:"affected", value:"OCS Inventory NG version 2.0.1 and prior.");

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

if (version_is_less(version: vers, test_version: "2.0.2")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "2.0.2", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
