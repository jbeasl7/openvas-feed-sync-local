# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902252");
  script_version("2024-11-14T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-11-14 05:05:31 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"creation_date", value:"2010-09-29 09:26:02 +0200 (Wed, 29 Sep 2010)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2010-0781");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere Application Server 6.1.x < 6.1.0.33 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_consolidation.nasl");
  script_mandatory_keys("ibm/websphere/detected");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote authenticated users to cause a
  denial of service (CPU consumption) via a crafted URL.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server (WAS) 6.1 before 6.1.0.33.");

  script_tag(name:"insight", value:"The flaw is due to unspecified error in the administrative console,
  which allows attackers to cause a denial of service.");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to an unspecified vulnerability.");

  script_tag(name:"solution", value:"Apply the fix pack 6.1.0.33 or later.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/61890");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1PM11807");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27007951");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "6.1", test_version_up: "6.1.0.33")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.0.33");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
