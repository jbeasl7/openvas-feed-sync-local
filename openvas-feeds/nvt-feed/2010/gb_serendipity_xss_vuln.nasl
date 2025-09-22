# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:s9y:serendipity";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801517");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-09-23 08:13:58 +0200 (Thu, 23 Sep 2010)");
  script_cve_id("CVE-2010-2957");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_name("Serendipity < 1.5.4 'serendipity_admin.php' XSS Vulnerability");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2010/08/29/3");
  script_xref(name:"URL", value:"http://blog.s9y.org/archives/223-Serendipity-1.5.4-released.html");
  script_xref(name:"URL", value:"http://www.htbridge.ch/advisory/xss_vulnerability_in_serendipity.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("serendipity_detect.nasl");
  script_mandatory_keys("Serendipity/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to steal cookie-based
  authentication credentials, disclosure or modification of sensitive data.");

  script_tag(name:"affected", value:"Serendipity prior to 1.5.4 and on all platforms.");

  script_tag(name:"insight", value:"The flaw exists due to failure in the
  'include/functions_entries.inc.php' script to properly sanitize user-supplied input in
  'serendipity[body]' variable.");

  script_tag(name:"solution", value:"Update to version 1.5.4 or later.");

  script_tag(name:"summary", value:"Serendipity is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:vers, test_version:"1.5.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.5.4");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
