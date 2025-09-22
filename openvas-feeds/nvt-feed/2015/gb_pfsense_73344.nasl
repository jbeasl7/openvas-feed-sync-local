# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pfsense:pfsense";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105329");
  script_cve_id("CVE-2015-2294", "CVE-2015-2295");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_version("2025-09-12T05:38:45+0000");

  script_name("pfSense XSS and CSRF Vulnerabilities (pfSense-SA-15_04.webgui)");

  script_xref(name:"URL", value:"https://www.pfsense.org/security/advisories/pfSense-SA-15_04.webgui.asc");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/73344");

  script_tag(name:"impact", value:"An attacker may exploit these issues to execute arbitrary script code in the browser of an unsuspecting
user in the context of the affected site, steal cookie-based authentication credentials, perform unauthorized actions, and disclose or modify
sensitive information. Other attacks may also be possible.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was discovered in the pfSense WebGUI that could lead to arbitrary file deletion.

Insufficient validation of the HTTP request origin and the 'deletefile' HTTP GET parameter in the '/system_firmware_restorefullbackup.php' script
can lead to arbitrary file deletion. A remote attacker can trick a log-in administrator into visiting a malicious page with CSRF exploit and delete
arbitrary files on the target system with root privileges.");

  script_tag(name:"solution", value:"Upgrade to pfSense 2.2.1 or later.");
  script_tag(name:"summary", value:"pfSense is prone to multiple cross-site scripting (XSS)
  vulnerabilities and a cross-site request forgery (CSRF) vulnerability.");
  script_tag(name:"affected", value:"pfSense < 2.2.1");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2015-08-21 15:06:51 +0200 (Fri, 21 Aug 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_pfsense_consolidation.nasl");
  script_mandatory_keys("pfsense/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!version = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(version_is_less(version:version, test_version:"2.2.1")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"2.2.1");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
