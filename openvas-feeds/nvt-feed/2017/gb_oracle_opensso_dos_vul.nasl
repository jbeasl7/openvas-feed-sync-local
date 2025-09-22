# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:opensso";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811405");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2016-2834");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");
  script_tag(name:"creation_date", value:"2017-08-01 15:25:23 +0530 (Tue, 01 Aug 2017)");
  script_name("Oracle OpenSSO 'Web Agents' DOS Vulnerability");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("secpod_sun_opensso_detect.nasl");
  script_mandatory_keys("Oracle/OpenSSO/detected");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91072");

  script_tag(name:"summary", value:"Oracle OpenSSO is prone to denial of service (DOS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in Network
  Security Services (NSS) before 3.23.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to
  cause memory corruption and application crash, or possibly other unspecified impact
  via unknown vectors.");

  script_tag(name:"affected", value:"Oracle OpenSSO 3.0.0.8.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the
  references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # nb: The version check below is completely broken and doesn't match the version 8.0 of "real" services exposed...

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(! openssoPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(! vers = get_app_version(cpe:CPE, port:openssoPort)){
  exit(0);
}

if(version_is_equal(version:vers, test_version:"3.0.0.8")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"See references");
  security_message(port:openssoPort, data:report);
  exit(0);
}

exit(99);
