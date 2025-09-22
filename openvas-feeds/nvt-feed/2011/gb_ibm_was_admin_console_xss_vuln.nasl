# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801999");
  script_version("2024-11-14T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-11-14 05:05:31 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"creation_date", value:"2011-11-04 14:37:49 +0530 (Fri, 04 Nov 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2009-2748");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere Application Server XSS Vulnerability (Nov 2011)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_consolidation.nasl");
  script_mandatory_keys("ibm/websphere/detected");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied
  input in the Administration Console, which allows the remote attacker to inject malicious script
  into a Web page.");

  script_tag(name:"impact", value:"Successful exploitation will let remote attackers to inject
  malicious script into a Web page. Further an attacker could use this vulnerability to steal the
  victim's cookie-based authentication credentials.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server version 6.1.x prior to
  6.1.0.29 and 7.1.x prior to 7.0.0.7.");

  script_tag(name:"solution", value:"Update to version 6.1.0.29, 7.0.0.7 or later.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54229");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37015");
  script_xref(name:"URL", value:"http://www.ibm.com/support/docview.wss?uid=swg1PK99481");
  script_xref(name:"URL", value:"http://www.ibm.com/support/docview.wss?uid=swg1PK92057");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "6.1", test_version_up: "6.1.0.29")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.0.29");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0", test_version_up: "7.0.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.0.7");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
