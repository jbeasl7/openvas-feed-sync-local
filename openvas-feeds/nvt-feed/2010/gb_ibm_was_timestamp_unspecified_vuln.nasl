# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902251");
  script_version("2024-11-14T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-11-14 05:05:31 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"creation_date", value:"2010-09-29 09:26:02 +0200 (Wed, 29 Sep 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2010-3186");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere Application Server 7.x < 7.0.0.13 WS-Security Policy Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_consolidation.nasl");
  script_mandatory_keys("ibm/websphere/detected");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to a vulnerability
  when using WS-Security enabled JAX-WS web service application.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is caused by an unspecified error when using a
  WS-Security enabled JAX-WS web service application while the WS-Security policy specifies
  'IncludeTimestamp'.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server version 7.x prior to
  7.0.0.13.");

  script_tag(name:"solution", value:"Update to 7.0.0.13 or later.");

  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2215");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24027708");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24027709");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21443736");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "7.0", test_version_up: "7.0.0.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.0.13");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
