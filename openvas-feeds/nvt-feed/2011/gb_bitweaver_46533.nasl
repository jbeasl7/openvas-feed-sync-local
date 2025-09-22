# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:bitweaver:bitweaver";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103092");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2011-02-25 13:54:37 +0100 (Fri, 25 Feb 2011)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_name("Bitweaver <= 2.8.1 'edit.php' HTML Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46533");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("secpod_bitweaver_detect.nasl");
  script_mandatory_keys("Bitweaver/installed");

  script_tag(name:"summary", value:"Bitweaver is prone to an HTML injection vulnerability because it
  fails to properly sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site. This may allow
  the attacker to steal cookie-based authentication credentials, control how the site is rendered to
  the user, or launch other attacks.");

  script_tag(name:"affected", value:"Bitweaver 2.8.1 is vulnerable. Other versions may also be
  affected.");

  script_tag(name:"solution", value:"Update to the latest version.");

  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less_equal(version: vers, test_version: "2.8.1")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"Less or equal to 2.8.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
