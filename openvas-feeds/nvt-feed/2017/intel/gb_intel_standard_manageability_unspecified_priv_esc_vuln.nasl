# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:intel:standard_manageability_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811810");
  script_version("2023-08-22T05:06:00+0000");
  script_cve_id("CVE-2017-5698");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"last_modification", value:"2023-08-22 05:06:00 +0000 (Tue, 22 Aug 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-17 17:43:00 +0000 (Thu, 17 Aug 2023)");
  script_tag(name:"creation_date", value:"2017-09-12 19:05:54 +0530 (Tue, 12 Sep 2017)");
  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Intel Standard Manageability Privilege Escalation Vulnerability");

  script_tag(name:"summary", value:"Intel Standard Manageability is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified error in
  an unspecified function.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct privilege escalation.");

  script_tag(name:"affected", value:"Intel Standard Manageability firmware
  versions 11.0.25.3001 and 11.0.26.3000.");

  script_tag(name:"solution", value:"Upgrade to firmware version 11.6.x.1xxx or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00082.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_intel_standard_manageability_detect.nasl");
  script_mandatory_keys("intel/ism/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(vers == "11.0.25.3001" || vers == "11.0.26.3000") {
  report = report_fixed_ver(installed_version:vers, fixed_version:"11.6.x.1xxx or later");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
