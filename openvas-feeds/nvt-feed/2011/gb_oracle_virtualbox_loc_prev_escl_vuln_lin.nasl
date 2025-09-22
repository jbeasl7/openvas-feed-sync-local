# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801582");
  script_version("2025-09-19T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-01-31 05:37:34 +0100 (Mon, 31 Jan 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2010-4414");
  script_name("Oracle VirtualBox Extensions Local Privilege Escalation Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("secpod_sun_virtualbox_detect_lin.nasl");
  script_mandatory_keys("Sun/VirtualBox/Lin/Ver");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujan2011.html#AppendixSUNS");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45876");

  script_tag(name:"impact", value:"Successful exploitation will let the local users gain
  escalated privileges.");

  script_tag(name:"affected", value:"Oracle VirtualBox version 4.0.");

  script_tag(name:"insight", value:"The flaw is caused by an unspecified error related to various
  extensions, which could allow local authenticated attackers to gain elevated privileges.");

  script_tag(name:"summary", value:"Oracle VirtualBox is prone to a local privilege escalation
  vulnerability.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_equal(version:vers, test_version:"4.0")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"Equal to 4.0", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
