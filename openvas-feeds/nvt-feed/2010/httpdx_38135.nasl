# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100491");
  script_version("2024-07-24T05:06:37+0000");
  script_tag(name:"last_modification", value:"2024-07-24 05:06:37 +0000 (Wed, 24 Jul 2024)");
  script_tag(name:"creation_date", value:"2010-02-09 12:21:13 +0100 (Tue, 09 Feb 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("httpdx 1.5.2 'USER' Command Remote Format String Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_httpdx_server_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("httpdx/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38135");

  script_tag(name:"summary", value:"The 'httpdx' program is prone to a remote format string
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker may exploit this issue to execute arbitrary code
  within the context of the affected application. Failed exploit attempts will result in a
  denial-of-service condition.");

  script_tag(name:"affected", value:"The issue affects httpdx 1.5.2. Other versions may also be
  affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:80);

if(!version = get_kb_item("httpdx/" + port + "/Ver"))
  exit(0);

if(version_is_equal(version:version, test_version:"1.5.2")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"None");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
