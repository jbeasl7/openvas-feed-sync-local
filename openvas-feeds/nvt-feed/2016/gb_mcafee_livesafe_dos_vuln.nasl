# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mcafee:livesafe";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808082");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2016-4535");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-10 12:35:00 +0000 (Tue, 10 May 2016)");
  script_tag(name:"creation_date", value:"2016-06-10 13:58:57 +0530 (Fri, 10 Jun 2016)");
  script_name("McAfee LiveSafe Denial of Service Vulnerability");

  script_tag(name:"summary", value:"McAfee LiveSafe is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the integer signedness
  error in the AV engine before DAT 8145.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service (memory corruption and crash).");

  script_tag(name:"affected", value:"McAfee LiveSafe Version 14.0.x.");

  script_tag(name:"solution", value:"As a workaround it is recommended to consider
  one of the following actions, if applicable:

  - Block the network access to the host at the relevant port, by adding an access rule to the appropriate firewall(s).

  - Remove or shutdown the service/product, in case it is not needed.

  - Shield the vulnerability by enabling an IPS signature, if available.");

  script_tag(name:"solution_type", value:"Workaround");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://bugs.chromium.org/p/project-zero/issues/detail?id=817");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39770");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_mcafee_livesafe_detect.nasl");
  script_mandatory_keys("McAfee/LiveSafe/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!livesafeVer = get_app_version(cpe:CPE)){
  exit(0);
}

livesafeVer = eregmatch( pattern:"^[0-9]+.[0-9]+", string:livesafeVer);
livesafeVer = livesafeVer[0];

if(!livesafeVer){
  exit(0);
}

if(version_is_equal(version:livesafeVer, test_version:"14.0"))
{
  report = report_fixed_ver(installed_version:livesafeVer, fixed_version:"Workaround");
  security_message(data:report);
  exit(0);
}

