# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zope:zope";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100455");
  script_version("2023-10-06T05:06:29+0000");
  script_tag(name:"last_modification", value:"2023-10-06 05:06:29 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"creation_date", value:"2010-01-20 10:52:14 +0100 (Wed, 20 Jan 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2010-1104");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zope XSS Vulnerability (Jan 2010)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_zope_http_detect.nasl");
  script_mandatory_keys("zope/detected");

  script_tag(name:"summary", value:"Zope is prone to a cross-site scripting (XSS) vulnerability
  because the application fails to properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site. This may help
  the attacker steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"Zope prior to versions 2.12.3, 2.11.6, 2.10.11, 2.9.12 or
  2.8.12.");

  script_tag(name:"solution", value:"Update to version 2.12.3, 2.11.6, 2.10.11, 2.9.12, 2.8.12 or
  later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37765");
  script_xref(name:"URL", value:"https://mail.zope.org/pipermail/zope-announce/2010-January/002229.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "2.12", test_version2: "2.12.2"))
  fixed = "2.12.3";

if (version_in_range(version: version[1], test_version: "2.11", test_version2: "2.11.5"))
  fixed = "2.11.6";

if (version_in_range(version: version[1], test_version: "2.10", test_version2: "2.10.10"))
  fixed = "2.10.11";

if (version_in_range(version: version[1], test_version: "2.9", test_version2: "2.9.11"))
  fixed = "2.9.12";

if (version_in_range(version: version[1], test_version: "2.8", test_version2: "2.8.11"))
  fixed = "2.8.12";

if (fixed) {
  report = report_fixed_ver(installed_version: version, fixed_version: fixed);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
