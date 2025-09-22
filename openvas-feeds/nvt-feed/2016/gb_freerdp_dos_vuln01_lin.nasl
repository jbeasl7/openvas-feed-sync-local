# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:freerdp_project:freerdp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809738");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2013-4118");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-06 17:18:00 +0000 (Fri, 06 Mar 2020)");
  script_tag(name:"creation_date", value:"2016-12-01 17:37:04 +0530 (Thu, 01 Dec 2016)");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_name("FreeRDP < 1.1.0-beta1 DoS Vulnerability - Linux");

  script_tag(name:"summary", value:"FreeRDP is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the NULL pointer
  dereference error within the application.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to cause a denial of service condition.");

  script_tag(name:"affected", value:"FreeRDP before 1.1.0-beta1 on Linux.");

  script_tag(name:"solution", value:"Update to version 1.1.0-beta1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2013/07/12/2");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61072");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2013/07/11/12");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_freerdp_detect_lin.nasl");
  script_mandatory_keys("FreeRDP/Linux/Ver");

  exit(0);
}

include("version_func.inc");
include("revisions-lib.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

# nb: Using revcomp to compare package version precisely
if(revcomp(a:version, b:"1.1.0-beta1") < 0) {
  report = report_fixed_ver(installed_version:version, fixed_version:"1.1.0-beta1", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
