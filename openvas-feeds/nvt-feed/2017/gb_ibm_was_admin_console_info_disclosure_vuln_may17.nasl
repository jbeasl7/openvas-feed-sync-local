# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810979");
  script_version("2024-11-14T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-11-14 05:05:31 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"creation_date", value:"2017-05-22 16:47:45 +0530 (Mon, 22 May 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-1137");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere Application Server Information Disclosure Vulnerability (swg21998469)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_consolidation.nasl");
  script_mandatory_keys("ibm/websphere/detected");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to an information
  disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists because IBM WebSphere Application Server has a
  potential for weaker than expected security with the Administrative Console due to some
  unspecified error.");

  script_tag(name:"impact", value:"Successful exploitation of this issue may allow a remote
  attacker to obtain sensitive information and gain unauthorized access to the admin console.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server versions 8.5.0.0 through
  8.5.5.11 and 8.0.0.0 through 8.0.0.13.");

  script_tag(name:"solution", value:"Update to version 8.0.0.14, 8.5.5.12 or later.");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21998469");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98419");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "8.0", test_version_up: "8.0.0.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.0.14");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.5", test_version_up: "8.5.5.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.5.12");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
