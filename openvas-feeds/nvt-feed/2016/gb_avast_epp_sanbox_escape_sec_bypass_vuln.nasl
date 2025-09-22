# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:avast:endpoint_protection_plus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810214");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2016-4025");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-04 19:03:00 +0000 (Fri, 04 Nov 2016)");
  script_tag(name:"creation_date", value:"2016-11-24 14:26:59 +0530 (Thu, 24 Nov 2016)");
  script_name("Avast Endpoint Protection Plus Sandbox Escape Security Bypass Vulnerability");

  script_tag(name:"summary", value:"Avast Endpoint Protection Plus is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a design flaw in the
  Avast DeepScreen feature.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to escape from a fully sandboxed process, furthermore attacker can also freely
  modify or infect or encrypt any existing file in the case of a ransomware attack.");

  script_tag(name:"affected", value:"Avast Endpoint Protection Plus version 8.x
  through 8.0.1609");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://labs.nettitude.com/blog/escaping-avast-sandbox-using-single-ioctl-cve-2016-4025");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_avast_endpoint_protection_plus_detect.nasl");
  script_mandatory_keys("Avast/Endpoint-Protection-Plus/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!avastVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(avastVer =~ "^8")
{
  if(version_in_range(version:avastVer, test_version:"8.0", test_version2:"8.0.1609"))
  {
    report = report_fixed_ver(installed_version:avastVer, fixed_version:"WillNotFix");
    security_message(data:report);
    exit(0);
  }
}
