# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:informix_dynamic_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808639");
  script_version("2025-07-03T05:42:54+0000");
  script_tag(name:"last_modification", value:"2025-07-03 05:42:54 +0000 (Thu, 03 Jul 2025)");
  script_tag(name:"creation_date", value:"2016-08-08 13:44:37 +0530 (Mon, 08 Aug 2016)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-03 03:16:00 +0000 (Sat, 03 Dec 2016)");

  script_cve_id("CVE-2016-0226");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM Informix Dynamic Server Privilege Escalation Vulnerability (Mar 2016) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_ibm_informix_dynamic_server_smb_login_detect.nasl");
  script_mandatory_keys("ibm/informix/dynamic_server/smb-login/detected");

  script_tag(name:"summary", value:"IBM Informix Dynamic Server is prone to a privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper restrict access to the 'nsrd',
  'nsrexecd', and 'portmap' executable files in client implementation.");

  script_tag(name:"impact", value:"Successful exploitation will allow local users to modify the
  binary for this service and thus execute code in the context of SYSTEM.");

  script_tag(name:"affected", value:"IBM Informix Dynamic Server version 11.70.xCn.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.

  Note: Please create an override for this result if the patch was applied.");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=630&uid=swg21978598");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/85198");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version =~ "^11\.70") {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
