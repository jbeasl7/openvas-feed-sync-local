# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800110");
  script_version("2025-05-06T05:40:10+0000");
  script_tag(name:"last_modification", value:"2025-05-06 05:40:10 +0000 (Tue, 06 May 2025)");
  script_tag(name:"creation_date", value:"2008-10-07 16:11:33 +0200 (Tue, 07 Oct 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 13:52:57 +0000 (Fri, 02 Feb 2024)");

  script_cve_id("CVE-2007-4850", "CVE-2008-0599", "CVE-2008-0674", "CVE-2008-2050",
                "CVE-2008-2051");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP < 5.2.6 Multiple Vulnerabilities (Aug 2008)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2007-4850: Error in curl/interface.c in the cURL library(libcurl), which could be exploited
  by attackers to bypass safe_mode security restrictions.

  - CVE-2008-0599: Error during path translation in cgi_main.c.

  - CVE-2008-0674: Buffer overflow error in PCRE when handling a character class containing a very
  large number of characters with codepoints greater than 255(UTF-8 mode).

  - CVE-2008-2050: Stack-based buffer overflow in FastCGI SAPI (fastcgi.c).

  - CVE-2008-2051: Unspecified error within the processing of incomplete multibyte characters in
  escapeshellcmd() API function");

  script_tag(name:"impact", value:"Successful exploitation could result in remote arbitrary code
  execution, security restrictions bypass, access to restricted files, denial of service.");

  script_tag(name:"affected", value:"PHP version prior to 5.2.6.");

  script_tag(name:"solution", value:"Update to version 5.2.6 or later.");

  script_xref(name:"URL", value:"http://pcre.org/changelog.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/27413");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/27786");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/29009");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://wiki.rpath.com/wiki/Advisories:rPSA-2008-0176");
  script_xref(name:"URL", value:"http://wiki.rpath.com/wiki/Advisories:rPSA-2008-0178");
  script_xref(name:"URL", value:"http://wiki.rpath.com/wiki/Advisories:rPSA-2008-0086");

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

if (version_is_less_equal(version: version, test_version: "5.2.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
