# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:bugzilla";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100892");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-11-05 13:21:25 +0100 (Fri, 05 Nov 2010)");
  script_cve_id("CVE-2010-3172", "CVE-2010-3764");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Bugzilla Response Splitting and Security Bypass Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44618");
  script_xref(name:"URL", value:"http://www.bugzilla.org/security/3.2.8/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("bugzilla_detect.nasl");
  script_mandatory_keys("bugzilla/installed");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"Bugzilla is prone to a response-splitting vulnerability and a security-
  bypass vulnerability.");

  script_tag(name:"impact", value:"Successfully exploiting these issues may allow an attacker to:

  - bypass certain security restrictions

  - obtain sensitive information

  - influence or misrepresent how web content is served, cached, or interpreted.

  This could aid in various attacks that try to install client users with a false sense of trust.");

  script_tag(name:"affected", value:"These issues affect versions prior to 3.2.9, 3.4.9, and 3.6.3.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!vers = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version:vers, test_version: "3.6", test_version2:"3.6.2") ||
    version_in_range(version:vers, test_version: "3.4", test_version2:"3.4.8") ||
    version_in_range(version:vers, test_version: "3.2", test_version2:"3.2.8")) {
  security_message(port:port);
  exit(0);
}

exit(0);