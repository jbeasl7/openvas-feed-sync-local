# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:bea:weblogic_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100494");
  script_version("2024-06-28T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2010-02-14 12:35:00 +0100 (Sun, 14 Feb 2010)");
  script_cve_id("CVE-2010-0073");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle WebLogic Server Node Manager 'beasvc.exe' RCE Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37926");
  script_xref(name:"URL", value:"http://intevydis.blogspot.com/2010/01/oracle-weblogic-1032-node-manager-fun.html");
  script_xref(name:"URL", value:"http://blogs.oracle.com/security/2010/02/security_alert_for_cve-2010-00.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technology/deploy/security/alerts/alert-cve-2010-0073.html");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_oracle_weblogic_consolidation.nasl");
  script_mandatory_keys("oracle/weblogic/detected");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the vendor advisory for details.");

  script_tag(name:"summary", value:"Oracle WebLogic Server is prone to a remote command-execution vulnerability
  because the software fails to restrict access to sensitive commands.

  Successful attacks can compromise the affected software and possibly the computer.

  Oracle WebLogic Server 10.3.2 is vulnerable, other versions may also be affected.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "10.3.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See reference");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
