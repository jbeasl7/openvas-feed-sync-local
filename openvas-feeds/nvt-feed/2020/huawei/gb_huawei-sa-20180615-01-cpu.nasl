# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107832");
  script_version("2022-12-26T10:12:01+0000");
  script_tag(name:"last_modification", value:"2022-12-26 10:12:01 +0000 (Mon, 26 Dec 2022)");
  script_tag(name:"creation_date", value:"2020-05-26 15:22:01 +0200 (Tue, 26 May 2020)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_cve_id("CVE-2018-3639", "CVE-2018-3640");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Side-Channel Vulnerability Variants 3a and 4 (huawei-sa-20180615-01-cpu)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Intel publicly disclosed new variants of the side-channel central processing unit (CPU) hardware vulnerabilities known as Spectre and Meltdown.");

  script_tag(name:"insight", value:"Intel publicly disclosed new variants of the side-channel central processing unit (CPU) hardware vulnerabilities known as Spectre and Meltdown. These variants known as 3A (CVE-2018-3640) and 4 (CVE-2018-3639), local attackers may exploit these vulnerabilities to cause information leak on the affected system. (Vulnerability ID: HWPSIRT-2018-05139 and HWPSIRT-2018-05140)The two vulnerabilities have been assigned two Common Vulnerabilities and Exposures (CVE) IDs: CVE-2018-3639 and CVE-2018-3640.Huawei has released software updates to fix these vulnerabilities. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"Local attackers may exploit these vulnerabilities to cause information leak on the affected system.");

  script_tag(name:"affected", value:"1288H V5 versions earlier than V100R005C00SPC117 (BIOS V081)

2288H V5 versions earlier than V100R005C00SPC117 (BIOS V081)

2488 V5 versions earlier than V100R005C00SPC500 (BIOS V095)

2488H V5 versions earlier than V100R005C00SPC203 (BIOS V095)

5288 V3 versions earlier than V100R003C00SPC706 (BIOS V399)

AR3600 versions V200R006C10

BH620 V2 versions earlier than V100R002C00SPC302 (BIOS V370)

BH621 V2 versions earlier than V100R002C00SPC301 (BIOS V370)

BH622 V2 versions earlier than V100R002C00SPC309 (BIOS V521)

BH640 V2 versions earlier than V100R002C00SPC307 (BIOS V521)

CH121 versions V100R001C00SPC305

CH121 V3 versions earlier than V100R001C00SPC261 (BIOS V399)

CH121 V5 versions earlier than V100R001C00SPC131 (BIOS V081)

CH121H V3 versions earlier than V100R001C00SPC121 (BIOS V399)

CH121L V3 versions earlier than V100R001C00SPC161 (BIOS V399)

CH121L V5 versions earlier than V100R001C00SPC131 (BIOS V081)

CH140 versions V100R001C00

CH140 V3 versions earlier than V100R001C00SPC181 (BIOS V399)

CH140L V3 versions earlier than V100R001C00SPC161 (BIOS V399)

CH220 versions V100R001C00

CH220 V3 versions earlier than V100R001C00SPC261 (BIOS V399)

CH221 versions V100R001C00

CH222 versions V100R002C00SPC305

CH222 V3 versions earlier than V100R001C00SPC261 (BIOS V399)

CH225 V3 versions earlier than V100R001C00SPC161 (BIOS V399)

CH226 V3 versions earlier than V100R001C00SPC181 (BIOS V399)

CH240 versions V100R001C00

CH242 versions V100R001C00

CH242 V3 versions earlier than V100R001C00SPC331 (BIOS V358)

CH242 V3 DDR4 versions earlier than V100R001C00SPC331 (BIOS V817)

CH242 V5 versions earlier than V100R001C00SPC121 (BIOS V095)

FusionCompute versions V100R006C00 V100R006C10

FusionCube versions V100R002C02 V100R002C30 V100R002C70

FusionSphere OpenStack versions V100R005C00 V100R005C10SPC700 V100R005C10SPC701 V100R006C00 V100R006C10 V1R6C00RC1SPC1B060

HUAWEI MateBook (HZ-W09/ HZ-W19/ HZ-W29) versions earlier than BIOS 1.52

HUAWEI MateBook B200/ MateBook D (PL-W09/ PL-W19/ PL-W29) versions earlier than BIOS 1.21

HUAWEI MateBook D (MRC-W10/ MRC-W50/ MRC-W60) versions earlier than BIOS 1.19

HUAWEI MateBook X Pro (MACH-W19/ MACH-W29) versions earlier than BIOS 1.12

Honor MagicBook (VLT-W50/ VLT-W60) versions earlier than BIOS 1.12

ManageOne versions 3.0.5 3.0.7 3.0.8 3.0.9

OceanStor 18500 versions V100R001C30SPC300

OceanStor 18500 V3 versions V300R003C00 V300R006C10SPC100

OceanStor 18500F V3 versions V300R006C10SPC100

OceanStor 18800 versions V100R001C30SPC300

OceanStor 18800 V3 versions V300R006C10SPC100

OceanStor 18800F versions V100R001C30SPC300

OceanStor 18800F V3 versions V300R006C10SPC100

OceanStor 5300 V3 versions V300R006C10SPC100

OceanStor 5500 V3 versions V300R006C10SPC100

OceanStor 5600 V3 versions V300R006C10SPC100

OceanStor 5800 V3 versions V300R006C10SPC100

OceanStor 6800 V3 versions V300R006C10SPC100

OceanStor HVS85T versions V100R001C00

OceanStor HVS88T versions V100R001C00

OceanStor ReplicationDirector versions V200R001C00

RH1288 V2 versions earlier than V100R002C00SPC640 (BIOS 520)

RH1288 V3 versions earlier than V100R003C00SPC706 (BIOS V399)

RH1288A V2 versions earlier than V100R002C00SPC710 (BIOS V521)

RH2265 V2 versions earlier than V100R002C00SPC510 (BIOS V519)

RH2268 V2 versions earlier than V100R002C00SPC609 (BIOS V519)

RH2285 V2 versions earlier than V100R002C00SPC511 (BIOS V521)

RH2285H V2 versions earlier than V100R002C00SPC511 (BIOS V521)

RH2288 V2 versions earlier than V100R002C00SPC610 (BIOS 520)

RH2288 V3 versions earlier than V100R003C00SPC706 (BIOS V399)

RH2288A V2 versions earlier than V100R002C00SPC710  (BIOS V521)

RH2288E V2 versions earlier than V100R002C00SPC302 (BIOS V519)

RH2288H V2 versions earlier than V100R002C00SPC620 (BIOS 520)

RH2288H V3 versions earlier than V100R003C00SPC706 (BIOS V399)

RH2485 V2 versions earlier than V100R002C00SPC713 (BIOS V521)

RH5885 V2 4S versions earlier than V100R001C02SPC306 (BIOS V038)

RH5885 V2 8S versions earlier than V100R001C02SPC306 (BIOS V062)

RH5885 V3 (E7V2) versions earlier than V100R003C01SPC127 (BIOS V358)

RH5885 V3 (E7V3&E7V4) versions earlier than V100R003C10SPC121 (BIOS V817)

RH5885H V3 (E7V2) versions earlier than V100R003C00SPC218 (BIOS V358)

RH5885H V3 (E7V3) versions earlier than V100R003C00SPC218 (BIOS V660)

RH5885H V3 (E7V4) versions earlier than V100R003C10SPC120 (BIOS V817)

RH8100 V3 (E7V2&E7V3) versions earlier than V100R003C00SPC229 (BIOS V698)

RH8100 V3 (E7V4) versions earlier than V100R003C00SPC229 (BIOS V817)

RSE6500 versions V500R002C00

SMC2.0 versions V100R003C10 V500R002C00

TaiShan200 2180K versions earlier than 1.1.0.SPC133(BIOS V135K)

TaiShan200 2280 versions earlier than 1.0.0.SPC133(BIOS V135)

TaiShan200 2280K versions earlier than 1.1.0.SPC133(BIOS V135K)

TaiShan200 5280 versions earlier than 1.2.0.SPC133(BIOS V135)

VP9630 versions V600R006C10

VP9660 versions V600R006C10

XH310 V3 versions earlier than V100R003C00SPC706 (BIOS V399)

XH321 V3 versions earlier than V100R003C00SPC706 (BIOS V399)

XH620 V3 versions earlier than V100R003C00SPC706 (BIOS V399)

XH622 V3 versions earlier than V100R003C00SPC706 (BIOS V399)

XH628 V3 versions earlier than V100R003C00SPC706 (BIOS V399)

iManager NetEco versions V600R007C00 V600R007C10 V600R007C11 V600R007C12 V600R007C20 V600R007C40 V600R008C00 V600R008C10 V600R008C20 V600R008C30

iManager NetEco 6000 versions V600R007C40 V600R007C60 V600R007C80 V600R007C90 V600R008C00");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20180615-01-cpu-en");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

cpe_list = make_list( "cpe:/o:huawei:ar3600_firmware" );

if( ! infos = get_app_version_from_list( cpe_list:cpe_list, nofork:TRUE ) )
  exit( 0 );

cpe = infos["cpe"];
version = toupper( infos["version"] );

patch = get_kb_item( "huawei/vrp/patch" );

if( cpe == "cpe:/o:huawei:ar3600_firmware" ) {
  if(version =~ "^V200R006C10") {
    if (!patch || version_is_less(version: patch, test_version: "V200R009C00SPC500")) {
      report = report_fixed_ver(installed_version: version, installed_patch: patch, fixed_version: "V200R009C00SPC500");
      security_message(port: 0, data: report);
      exit(0);
    }
  }
}

exit( 99 );
