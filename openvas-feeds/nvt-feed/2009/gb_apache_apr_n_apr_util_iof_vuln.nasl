# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800679");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-08-17 14:35:19 +0200 (Mon, 17 Aug 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2412");
  script_name("Apache APR and APR-util Multiple Integer Overflow Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_apache_apr-utils_detect.nasl", "gb_apache_apr_detect.nasl");
  script_mandatory_keys("Apache/APR_or_Utils/Installed");

  script_xref(name:"URL", value:"http://www.apache.org/dist/apr/patches/apr-0.9-CVE-2009-2412.patch");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35949");
  script_xref(name:"URL", value:"http://www.apache.org/dist/apr/patches/apr-util-0.9-CVE-2009-2412.patch");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code in
  the context of an affected application, and can cause Denial of Service.");

  script_tag(name:"affected", value:"Apache APR version 0.9.x and 1.3.x before 1.3.8

  Apache APR-Utils version 0.9.x and 1.3.x before 1.3.9");

  script_tag(name:"insight", value:"The following issues exist:

  - An error exists when vectors trigger crafted calls to the allocator_alloc
  or apr_palloc function in memory/unix/apr_pools.c in APR.

  - An error in apr_rmm_malloc, apr_rmm_calloc or apr_rmm_realloc function in
  misc/apr_rmm.c is caused while aligning relocatable memory blocks in APR-util.");

  script_tag(name:"summary", value:"Apache APR and APR-Util is prone to multiple Integer Overflow vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to Apache APR version 1.3.8 or APR-util version 1.3.9 or
  apply the patches for Apache APR-Utils 0.9.x or Apache APR version 0.9.x. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:apache:apr-util", "cpe:/a:apache:portable_runtime");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];
cpe  = infos["cpe"];

if("apr-util" >< cpe) {
  if(version_in_range(version:vers, test_version:"0.9.0", test_version2:"0.9.17") ||
     version_in_range(version:vers, test_version:"1.3.0", test_version2:"1.3.8")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"1.3.9", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
} else if("portable_runtime" >< cpe) {
  if(version_in_range(version:vers, test_version:"0.9.0", test_version2:"0.9.18") ||
     version_in_range(version:vers, test_version:"1.3.0", test_version2:"1.3.7")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"1.3.8", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
