# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:open-xchange:open-xchange_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806526");
  script_version("2024-03-04T14:37:58+0000");
  script_cve_id("CVE-2015-5375");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-11-02 12:36:19 +0530 (Mon, 02 Nov 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Open-Xchange (OX) Server Object Properties Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"Open-Xchange (OX) Server is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to insufficient
  sanitization of user supplied input via unknown vectors related to object
  properties.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML in the browser of an
  unsuspecting user in the context of the affected site.");

  script_tag(name:"affected", value:"Open-Xchange (OX) Server version 6 and
  prior.");

  script_tag(name:"solution", value:"Upgrade to Open-Xchange (OX) Server version
  6.22.9-rev15m or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/536523/100/0/threaded");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76837");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ox_server_detect.nasl");
  script_mandatory_keys("open_xchange_server/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

revision = get_kb_item("open_xchange_server/" + port + "/rev");

if(revision) {
  ## Updating version with revision number
  version = version + "." + revision;

  if(version =~ "^6\.") {
    if(version_is_equal(version:version, test_version:"6.22.9")) {
      report = report_fixed_ver(installed_version:version, fixed_version:"6.22.9-rev15m");
      security_message(data:report, port:port);
      exit(0);
    }
  }
}

exit(99);
