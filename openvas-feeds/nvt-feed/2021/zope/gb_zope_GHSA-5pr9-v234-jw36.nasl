# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zope:zope";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146015");
  script_version("2023-10-06T05:06:29+0000");
  script_tag(name:"last_modification", value:"2023-10-06 05:06:29 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"creation_date", value:"2021-05-26 05:03:57 +0000 (Wed, 26 May 2021)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-27 14:12:00 +0000 (Thu, 27 May 2021)");

  script_cve_id("CVE-2021-32633");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zope RCE Vulnerability (GHSA-5pr9-v234-jw36)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_zope_http_detect.nasl");
  script_mandatory_keys("zope/detected");

  script_tag(name:"summary", value:"Zope is prone to a remote code execution (RCE) vulnerability
  via a traversal in TAL expressions.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Most Python modules are not available for using in TAL
  expressions that you can add through-the-web, for example in Zope Page Templates. This
  restriction avoids file system access, for example via the 'os' module. But some of the untrusted
  modules are available indirectly through Python modules that are available for direct use.

  By default, you need to have the Manager role to add or edit Zope Page Templates through the web.
  Only sites that allow untrusted users to add/edit Zope Page Templates through the web are at
  risk.");

  script_tag(name:"affected", value:"Zope prior to version 4.6 and 5.2.");

  script_tag(name:"solution", value:"Update to version 4.6, 5.2 or later.");

  script_xref(name:"URL", value:"https://github.com/zopefoundation/Zope/security/advisories/GHSA-5pr9-v234-jw36");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "4.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.6");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0", test_version2: "5.1.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
