# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vmware:player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107211");
  script_version("2024-11-22T15:40:47+0000");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"creation_date", value:"2017-05-30 11:31:00 +0200 (Tue, 30 May 2017)");
  script_cve_id("CVE-2017-4915", "CVE-2017-4916");

  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_tag(name:"qod_type", value:"executable_version");
  script_name("Multiple VMware Workstation Products DLL Loading Local Privilege Escalation Vulnerability - Linux");
  script_tag(name:"summary", value:"VMware Workstation and Horizon View Client are prone to a remote
  code execution (RCE) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"VMware Workstation Pro/Player contains an insecure library loading vulnerability via ALSA sound driver configuration files. Successful exploitation of this issue may allow unprivileged host users to escalate their privileges to root in a Linux host machine.");
  script_tag(name:"impact", value:"Successfully exploiting this issue allows attackers to execute arbitrary code in the context of the affected application. Failed exploits will result in denial-of-service conditions.");
  script_tag(name:"affected", value:"12.5.6");
  script_tag(name:"solution", value:"Update to VMWare Workstation Player 12.5.6. Please see the references or vendor advisory for more information.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98566");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2017-0009.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");

  script_family("Privilege escalation");

  script_dependencies("gb_vmware_prdts_detect_lin.nasl");
  script_mandatory_keys("VMware/Player/Linux/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!Ver = get_app_version(cpe:CPE)){
  exit(0);
}

if (Ver =~ "^12\."){

  if(version_is_less(version: Ver, test_version:"12.5.6")){
    report = report_fixed_ver(installed_version:Ver, fixed_version:"12.5.6");
    security_message(data:report);
    exit( 0 );
  }
}

exit ( 99 );
