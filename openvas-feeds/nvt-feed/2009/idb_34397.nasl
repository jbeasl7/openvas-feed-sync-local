# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:idb:idb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100110");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-04-07 09:57:50 +0200 (Tue, 07 Apr 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1498");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("iDB 'skin' Parameter Local File Include Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("idb_detect.nasl");
  script_mandatory_keys("idb/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"iDB (Internet Discussion Boards) is prone to a local file-include
  vulnerability because it fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to view and execute arbitrary
  local files in the context of the webserver process. This may aid in further attacks.");

  script_tag(name:"affected", value:"iDB 0.2.5 Pre-Alpha SVN 243 is vulnerable, other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
  a newer release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34397");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (ereg(pattern: "^0.2.5 SVN 243$", string: version)) {
  report = report_fixed_ver(installed_version:version, fixed_version:"None");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);