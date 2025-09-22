# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:hp:loadrunner";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810328");
  script_version("2024-06-28T05:05:33+0000");
  script_cve_id("CVE-2016-8512");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-09 17:39:00 +0000 (Fri, 09 Mar 2018)");
  script_tag(name:"creation_date", value:"2017-01-10 12:29:27 +0530 (Tue, 10 Jan 2017)");
  script_name("HPE LoadRunner MMS Protocol RCE Vulnerability");

  script_tag(name:"summary", value:"HPE LoadRunner is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an unspecified buffer
  overflow condition in the MMS protocol due to improper validation of
  user-supplied input.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  unauthenticated remote attacker to cause a denial of service or the execution
  of arbitrary code.");

  script_tag(name:"affected", value:"HPE LoadRunner version 12.53.1203.0 and prior.");

  script_tag(name:"solution", value:"HPE has released the following mitigation information to resolve the vulnerability in impacted versions of HPE LoadRunner and Performance Center.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://h20565.www2.hpe.com/hpsc/doc/public/display?docLocale=en_US&docId=emr_na-c05354136");
  script_xref(name:"URL", value:"https://softwaresupport.hp.com/group/softwaresupport/search-result/-/facetsearch/document/KM02608184");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_hpe_loadrunner_detect.nasl");
  script_mandatory_keys("HPE/LoadRunner/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!hpVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less_equal(version:hpVer, test_version:"12.53.1203.0"))
{
  report = report_fixed_ver(installed_version:hpVer, fixed_version:"See Vendor");
  security_message(data:report);
  exit(0);
}
