# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:intel:active_management_technology_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812222");
  script_version("2024-08-23T15:40:37+0000");
  script_tag(name:"last_modification", value:"2024-08-23 15:40:37 +0000 (Fri, 23 Aug 2024)");
  script_tag(name:"creation_date", value:"2017-11-22 13:16:37 +0530 (Wed, 22 Nov 2017)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-22 16:18:00 +0000 (Mon, 22 May 2023)");

  script_cve_id("CVE-2017-5711", "CVE-2017-5712");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Intel Active Management Technology Multiple Buffer Overflow Vulnerabilities (INTEL-SA-00086)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_intel_amt_http_detect.nasl");
  script_mandatory_keys("intel/amt/detected");

  script_tag(name:"summary", value:"Intel Active Management Technology is prone to multiple buffer
  overflow vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple unspecified buffer overflow
  errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute
  arbitrary code with AMT execution privilege.");

  script_tag(name:"affected", value:"Intel AMT for Intel ME Firmware versions 8.x, 9.x, 10.x,
  11.0.x.x, 11.5.x.x, 11.6.x.x, 11.7.x.x, 11.10.x.x and 11.20.x.x.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00086.html");
  script_xref(name:"URL", value:"https://thehackernews.com/2017/11/intel-chipset-flaws.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^(8|9|10|(11\.(0|5|6|7|10|20)))") {
  report = report_fixed_ver(installed_version: version, fixed_version:"See advisory");
  security_message(port :port, data: report);
  exit(0);
}

exit(99);
