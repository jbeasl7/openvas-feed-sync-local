# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:realnetworks:realplayer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809399");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2016-9018");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-29 19:20:00 +0000 (Tue, 29 Nov 2016)");
  script_tag(name:"creation_date", value:"2016-11-03 11:05:43 +0530 (Thu, 03 Nov 2016)");
  script_name("RealNetworks RealPlayer 'QCP' Denial of Service Vulnerability - Windows");

  script_tag(name:"summary", value:"RealPlayer is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an improper handling
  of a repeating VRAT chunk in qcpfformat.dll.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a Null pointer dereference and to crash the application.");

  script_tag(name:"affected", value:"RealNetworks RealPlayer version 18.1.5.705
  on Windows.");

  script_tag(name:"solution", value:"Update RealPlayer to version 18.1.6.161");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40617");
  script_xref(name:"URL", value:"https://customer.real.com/hc/en-gb/articles/214793317-RealNetworks-product-security-updates");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_realplayer_detect_win.nasl");
  script_mandatory_keys("RealPlayer/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!realVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_equal(version:realVer, test_version:"18.1.5.705"))
{
  report = report_fixed_ver(installed_version:realVer, fixed_version:"18.1.6.161");
  security_message(data:report);
  exit(0);
}
