# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:hp:web_jetadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812516");
  script_version("2025-09-12T05:38:45+0000");
  script_cve_id("CVE-2017-2742");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-02-20 15:39:57 +0530 (Tue, 20 Feb 2018)");
  script_name("HP Web Jetadmin Unspecified Denial of Service Vulnerability");

  script_tag(name:"summary", value:"HP Web Jetadmin is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in HP Web
  JetAdmin. A remote user can cause denial of service conditions on the
  target system.

  No details are available.");

  script_tag(name:"impact", value:"Successfully exploitation will allow an attacker
  to cause denial-of-service condition.");

  script_tag(name:"affected", value:"HP Web Jetadmin versions before 10.4 SR2");

  script_tag(name:"solution", value:"Upgrade to version 10.4 SR2 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102829");
  script_xref(name:"URL", value:"https://securitytracker.com/id/1038760");
  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/c05541534");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_dependencies("gb_hp_web_jetadmin_detect.nasl");
  script_mandatory_keys("HpWebJetadmin/installed");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

# HP Web Jetadmin 10.4 SR2->10.4.101995
if(version_is_less(version:version, test_version:"10.4.101995")){
  report = report_fixed_ver(installed_version:version, fixed_version:"10.4 SR2 ", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
