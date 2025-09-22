# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:soliddb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100722");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2010-07-21 19:56:46 +0200 (Wed, 21 Jul 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-2771");

  script_name("IBM SolidDB 'solid.exe' Handshake RCE Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41653");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21439148");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-125/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_ibm_soliddb_detect.nasl");
  script_mandatory_keys("IBM-soliddb/installed");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor released updates to address this issue. Please see the
  references for more information.");

  script_tag(name:"summary", value:"IBM SolidDB is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary code with
  SYSTEM user privileges. Failed exploit attempts will result in a denial-of-service condition.");

  script_tag(name:"affected", value:"The vulnerability is reported in version 6.5 FP1 (6.5.0.1). Prior
  versions may also be affected.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!get_app_version(cpe: CPE, port: port))
  exit(0);

if(!v = get_kb_item(string("soliddb/",port,"/version")))
  exit(0);

if("Build" >< v) {
  version = eregmatch(pattern:"^[^ ]+", string:v);
  version = version[0];
} else {
  version = v;
}

if(version_is_less_equal(version:version, test_version:"6.5.0.1")) {
  report = report_fixed_ver(installed_version:version, vulnerable_range:"Less or equal to 6.5.0.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
