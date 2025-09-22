# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:bugzilla";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100749");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-08-09 13:36:05 +0200 (Mon, 09 Aug 2010)");
  script_cve_id("CVE-2010-2756", "CVE-2010-2757", "CVE-2010-2758", "CVE-2010-2759");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("Bugzilla Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42275");
  script_xref(name:"URL", value:"http://www.bugzilla.org/security/3.2.7/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("bugzilla_detect.nasl");
  script_mandatory_keys("bugzilla/installed");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"Bugzilla is prone to the following vulnerabilities:

1. A security bypass issue.

2. Multiple information disclosure vulnerabilities.

3. A denial-of-service vulnerability.

Successfully exploiting these issues may allow an attacker to bypass certain security restrictions, obtain
sensitive information or cause the affected application to crash, denying service to legitimate users.

The following versions are vulnerable:

4.x and 3.2.x versions prior to 3.2.8, 4.1.x and 3.4.x versions prior to 3.4.8, 4.2.x and 3.6.x versions prior to
3.6.2, 4.3.x versions prior to 3.7.3.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!vers = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version:vers, test_version: "2", test_version2:"3.2.7") ||
    version_in_range(version:vers, test_version: "3.3", test_version2:"3.4.7") ||
    version_in_range(version:vers, test_version: "3.5", test_version2:"3.6.1") ||
    version_in_range(version:vers, test_version: "3.7", test_version2:"3.7.2")){
  security_message(port:port);
  exit(0);
}

exit(0);
