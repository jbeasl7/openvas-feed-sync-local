# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:infoblox:netmri";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103576");
  script_version("2025-06-09T05:41:14+0000");
  script_tag(name:"last_modification", value:"2025-06-09 05:41:14 +0000 (Mon, 09 Jun 2025)");
  script_tag(name:"creation_date", value:"2012-09-25 12:37:48 +0200 (Tue, 25 Sep 2012)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Infoblox NetMRI Multiple XSS Vulnerabilities (Nov 2011)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_infoblox_netmri_consolidation.nasl");
  script_mandatory_keys("infoblox/netmri/detected");

  script_tag(name:"summary", value:"Infoblox NetMRI is prone to multiple cross-site scripting (XSS)
  vulnerabilities because it fails to properly sanitize user-supplied input before using it in
  dynamically generated content.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker may leverage these issues to execute arbitrary
  script code in the browser of an unsuspecting user in the context of the affected site. This can
  allow the attacker to steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"Infoblox NetMRI versions 6.2.1, 6.1.2, and 6.0.2.42 are
  vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"Reportedly the vendor has released an update to fix the
  issue.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50646");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2011/Nov/158");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_equal(version: version, test_version: "6.2.1") ||
    version_is_equal(version: version, test_version: "6.1.2") ||
    version_is_equal(version: version, test_version: "6.0.2.42")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See references");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
