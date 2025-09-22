# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103276");
  script_version("2024-11-26T07:35:52+0000");
  script_tag(name:"last_modification", value:"2024-11-26 07:35:52 +0000 (Tue, 26 Nov 2024)");
  script_tag(name:"creation_date", value:"2011-09-28 12:51:43 +0200 (Wed, 28 Sep 2011)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2011-1411");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere Application Server 7.x < 7.0.0.19 OpenSAML XML Signature Wrapping Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_consolidation.nasl");
  script_mandatory_keys("ibm/websphere/detected");

  script_tag(name:"summary", value:"IBM WebSphere Application Server ships a OpenSAML
  implementation which is prone to a security vulnerability involving XML signature wrapping.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploits may allow unauthenticated attackers to
  construct specially crafted messages that can be successfully verified and contain arbitrary
  content. This may aid in further attacks.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server version 7.x prior to
  7.0.0.19.");

  script_tag(name:"solution", value:"Update to version 7.0.0.19 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48890");
  script_xref(name:"URL", value:"https://spaces.internet2.edu/display/OpenSAML/Home/");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27014463");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "7.0", test_version_up: "7.0.0.19")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.0.19");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
