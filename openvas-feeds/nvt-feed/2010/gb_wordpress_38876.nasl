# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100549");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-03-24 17:54:30 +0100 (Wed, 24 Mar 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("WordPress Password Protection Security Bypass Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38876");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2010/Mar/361");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/detected");

  script_tag(name:"summary", value:"WordPress is prone to a security bypass vulnerability.");

  script_tag(name:"impact", value:"Attackers may exploit this issue to access certain content that may
  contain sensitive information.");

  script_tag(name:"affected", value:"WordPress 2.9.2 and 2.0.11 are vulnerable. Other versions may also
  be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less_equal(version: vers, test_version: "2.9.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"None");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
