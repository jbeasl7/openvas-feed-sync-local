# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:bluecoat:reporter";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103246");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2011-09-08 15:23:37 +0200 (Thu, 08 Sep 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("Blue Coat Reporter Directory Traversal Vulnerability");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_blue_coat_reporter_detect.nasl");
  script_mandatory_keys("bluecoat/reporter/detected");
  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Blue Coat Reporter is prone to a directory traversal vulnerability
  because it fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"Exploiting this issue will allow an attacker to view arbitrary local
  files within the context of the Web server. Information harvested may
  aid in launching further attacks.");

  script_tag(name:"affected", value:"Blue Coat Reporter versions prior to 9.3 are vulnerable.");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49482");
  script_xref(name:"URL", value:"https://kb.bluecoat.com/index?page=content&id=SA60");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:vers, test_version:"9.3.1.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"9.3.1.1");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
