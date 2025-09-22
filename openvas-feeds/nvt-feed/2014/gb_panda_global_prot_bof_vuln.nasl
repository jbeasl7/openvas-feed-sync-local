# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pandasecurity:panda_global_protection_2014";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804906");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2014-5307");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-09-22 16:48:04 +0530 (Mon, 22 Sep 2014)");

  script_name("Panda Global Protection Heap Based Buffer Overflow (Sep 2014)");

  script_tag(name:"summary", value:"Panda Global Protection is prone to heap based buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw exists due to improper bounds checking
  by the PavTPK.sys kernel mode driver.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause a heap-based buffer overflow by sending a specially crafted IOCTL request
  and execute arbitrary code on the system with kernel-level privileges.");

  script_tag(name:"affected", value:"Panda Global Protection 2014 7.01.01");

  script_tag(name:"solution", value:"Apply the hotfix 'hft131306s24_r1'.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/95382");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69293");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/127948/Panda-Security-2014-Privilege-Escalation.html");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Buffer overflow");
  script_dependencies("gb_panda_prdts_detect.nasl");
  script_mandatory_keys("Panda/GlobalProtection/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!version = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_equal(version:version, test_version:"7.01.01"))
{
  report = report_fixed_ver(installed_version:version, vulnerable_range:"Equal to 7.01.01");
  security_message(port:0, data:report);
  exit(0);
}
