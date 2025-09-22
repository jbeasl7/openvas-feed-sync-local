# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:bea:weblogic_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100714");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-07-14 13:50:55 +0200 (Wed, 14 Jul 2010)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_cve_id("CVE-2010-2375");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle WebLogic Server Encoded URL Remote Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41620");
  script_xref(name:"URL", value:"http://www.vsecurity.com/resources/advisory/20100713-1/");
  script_xref(name:"URL", value:"http://www.oracle.com/technology/deploy/security/critical-patch-updates/cpujul2010.html");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_oracle_weblogic_consolidation.nasl");
  script_mandatory_keys("oracle/weblogic/detected");

  script_tag(name:"solution", value:"Vendor updates are available. Please contact the vendor for more information.");

  script_tag(name:"summary", value:"Oracle WebLogic Server is prone to a remote vulnerability.

  The vulnerability can be exploited over the 'HTTP' protocol. For an exploit to succeed, the attacker must have
  'Plugins for Apache, Sun and IIS web servers' privileges.

  This vulnerability affects the following supported versions:

  7. SP7, 8.1 SP6, 9.0, 9.1, 9.2 MP3, 10.0 MP2, 10.3.2, 10.3.3");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "10.3.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See reference");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
