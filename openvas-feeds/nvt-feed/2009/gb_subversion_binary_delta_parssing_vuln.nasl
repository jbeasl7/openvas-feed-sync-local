# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:subversion:subversion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101104");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-08-20 09:27:17 +0200 (Thu, 20 Aug 2009)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2411");
  script_name("Subversion Binary Delta Processing Multiple Integer Overflow Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_subversion_detect.nasl");
  script_mandatory_keys("subversion/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/36184/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35983");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Aug/1022697.html");
  script_xref(name:"URL", value:"http://subversion.tigris.org/security/CVE-2009-2411-advisory.txt");

  script_tag(name:"impact", value:"Attackers can exploit these issues to compromise an application using the library
  or crash the application, resulting into a denial of service conditions.");

  script_tag(name:"affected", value:"Subversion version 1.5.6 and prior,
  Subversion version 1.6.0 through 1.6.3.");

  script_tag(name:"insight", value:"The flaws are due to input validation errors in the processing of svndiff
  streams in the 'libsvn_delta' library.");

  script_tag(name:"solution", value:"Apply the patch from the linked references or upgrade to Subversion version 1.5.7 or 1.6.4.");

  script_tag(name:"summary", value:"Subversion is prone to multiple Integer Overflow Vulnerabilities.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

location = infos["location"];
version = infos["version"];

if(version_is_less(version:version, test_version:"1.5.7") ||
   version_in_range(version:version, test_version:"1.6", test_version2:"1.6.3")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"1.5.7/1.6.4", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
