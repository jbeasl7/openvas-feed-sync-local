# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:appserver:io";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811268");
  script_version("2024-03-04T14:37:58+0000");
  script_cve_id("CVE-2015-1847");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-04 17:00:00 +0000 (Fri, 04 Aug 2017)");
  script_tag(name:"creation_date", value:"2017-08-02 11:04:18 +0530 (Wed, 02 Aug 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("appserver.io Application Server Directory Traversal Vulnerability");

  script_tag(name:"summary", value:"appserver.io application server is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to error in the bundled
  webserver's HTTP parsing library, URI as coming from a web client was not
  normalized correctly.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to traversal movement through the file system of the host without
  the restriction of the configured document root. This allowed for access of
  otherwise inaccessible files through specially crafted HTTP requests.");

  script_tag(name:"affected", value:"appserver.io Application Server before
  version 1.0.3");

  script_tag(name:"solution", value:"Upgrade to appserver.io version 1.0.3 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://appserver.io/security/2015/03/31/traversal-directory-vulnerability-in-webserver.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_appserver_io_application_server_detect.nasl");
  script_mandatory_keys("appserver/io/ApplicationServer/ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:version, test_version:"1.0.3")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"1.0.3");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
