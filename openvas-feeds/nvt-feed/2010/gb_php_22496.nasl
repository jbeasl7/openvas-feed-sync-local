# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100606");
  script_version("2025-05-06T05:40:10+0000");
  script_tag(name:"last_modification", value:"2025-05-06 05:40:10 +0000 (Tue, 06 May 2025)");
  script_tag(name:"creation_date", value:"2010-04-23 13:12:25 +0200 (Fri, 23 Apr 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2007-0905", "CVE-2007-0906", "CVE-2007-0907", "CVE-2007-0908",
                "CVE-2007-0909", "CVE-2007-0910");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP <= 4.4.4 / 5.0 <= 5.2.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to multiple security vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploits could allow an attacker to write files in
  unauthorized locations, cause a denial of service (DoS) condition, and potentially execute
  code.");

  script_tag(name:"affected", value:"PHP versions 4.x through 4.4.4 and 5.x through 5.2.0. Other
  versions may also be vulnerable.");

  script_tag(name:"solution", value:"The vendor has released updates to address these issues.
  Contact the vendor for details on obtaining and applying the appropriate updates.

  Please see the advisories for more information.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/22496");
  script_xref(name:"URL", value:"http://support.avaya.com/elmodocs2/security/ASA-2007-136.htm");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php#5.2.1");
  script_xref(name:"URL", value:"http://www.php.net/releases/5_2_1.php");
  script_xref(name:"URL", value:"http://support.avaya.com/elmodocs2/security/ASA-2007-101.htm");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2007-0076.html");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2007-0081.html#Red%20Hat%20Linux%20Advanced%20Workstation%202.1%20for%20the%20Itanium%20Processor");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2007-0082.html");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2007-0089.html");
  script_xref(name:"URL", value:"http://www.novell.com/linux/security/advisories/2007_44_php.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "4.0.0", test_version2: "4.4.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "5.2.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
