# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:invision_power_services:invision_power_board";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100794");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2010-3424");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-09-09 16:30:22 +0200 (Thu, 09 Sep 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Invision Power Board <= 3.1.2 BBCode XSS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("invision_power_board_detect.nasl");
  script_mandatory_keys("invision_power_board/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43053");
  script_xref(name:"URL", value:"http://community.invisionpower.com/topic/320838-ipboard-31x-security-patch-released/");

  script_tag(name:"summary", value:"Invision Power Board is prone to a cross-site scripting (XSS)
  vulnerability because it fails to sufficiently sanitize user-supplied data.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary HTML and
  script code in the browser of an unsuspecting user in the context of the affected site. This may
  allow the attacker to steal cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"affected", value:"Invision Power Board 3.1.2 is vulnerable. Other versions may also
  be affected.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less_equal(version:vers, test_version:"3.1.2")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"Less than or equal to 3.1.2");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
