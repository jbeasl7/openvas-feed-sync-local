# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804123");
  script_version("2025-09-19T05:38:25+0000");
  script_cve_id("CVE-2013-3792");
  script_tag(name:"cvss_base", value:"3.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2013-10-28 09:51:57 +0530 (Mon, 28 Oct 2013)");
  script_name("Oracle VirtualBox Local Denial of Service Vulnerability-01 (Oct 2013) - Linux");

  script_tag(name:"summary", value:"Oracle VirtualBox is prone to an unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"insight", value:"The flaw is due to unspecified errors related to 'core' component");

  script_tag(name:"affected", value:"Oracle VirtualBox version 3.2.18 and before, 4.0.20 and before, 4.1.28
  and before, 4.2.18 and before on Linux.");

  script_tag(name:"impact", value:"Successful exploitation will allow local users to affect availability
  and cause local denial of service.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/53858");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60794");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_sun_virtualbox_detect_lin.nasl");
  script_mandatory_keys("Sun/VirtualBox/Lin/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:oracle:vm_virtualbox", "cpe:/a:sun:virtualbox");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"3.2.0", test_version2:"3.2.17") ||
   version_in_range(version:vers, test_version:"4.0.0", test_version2:"4.0.19") ||
   version_in_range(version:vers, test_version:"4.1.0", test_version2:"4.1.27") ||
   version_in_range(version:vers, test_version:"4.2.0", test_version2:"4.2.17")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See vendor advisory", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
