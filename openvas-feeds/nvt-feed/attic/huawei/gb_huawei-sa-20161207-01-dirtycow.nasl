# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108768");
  script_version("2024-07-25T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-07-25 05:05:41 +0000 (Thu, 25 Jul 2024)");
  script_tag(name:"creation_date", value:"2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-24 14:27:14 +0000 (Wed, 24 Jul 2024)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2016-5195");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Dirty COW Vulnerability in Huawei Products (huawei-sa-20161207-01-dirtycow)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei");

  script_tag(name:"summary", value:"In the morning of October 21th, 2016, a security researcher Phil Oester disclosed a local privilege escalation vulnerability in Linux kernel.

  This VT has been deprecated and is therefore no longer functional.");

  script_tag(name:"insight", value:"In the morning of October 21th, 2016, a security researcher Phil Oester disclosed a local privilege escalation vulnerability in Linux kernel. A race condition was found in the way the Linux kernel's memory subsystem handled the copy-on-write (COW) breakage of private read-only memory mappings. An unprivileged local user could exploit this vulnerability to gain write access to otherwise read-only memory mappings and thus obtain the highest privileges on the system. (Vulnerability ID: HWPSIRT-2016-10050)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2016-5195.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to escalate the privilege levels to obtain administrator privilege.");

  script_tag(name:"affected", value:"5288 V3 versions V100R003C00

9032 versions V100R001C00 V100R001C00SPC101 V100R001C00SPC200

AC6605 versions V200R006C00

Agile Controller-Campus versions V100R002C00 V100R002C10 V100R002C10SPC400 V100R002C10SPC403

Austin versions V100R001C10B290 V100R001C10B680 V100R001C20B110 V100R001C30 V100R001C50

BH620 V2 versions V100R002C00

BH621 V2 versions V100R002C00

BH622 V2 versions V100R002C00

BH640 V2 versions V100R002C00

Balong GU versions V800R200C50B200 V800R200C55B200

Balong GUL versions V700R110C30 V700R110C31 V700R200C00 V700R220C30 V700R500C30 V700R500C31

CAM-L21 versions earlier than C576B130

CH121 V3 versions V100R001C00

CH140 V3 versions V100R001C00

CH220 V3 versions V100R001C00

CH222 V3 versions V100R001C00

CH225 V3 versions V100R001C00

CH226 V3 versions V100R001C00

Carrier-eLog versions V200R003C10

Chicago versions V100R001C10

CloudOpera CSM versions SysTool(OSUpgrade)V200R016C10SPC100 SysTool(OSUpgrade)V200R016C10SPC100B021 V200R016C10SPC600

Dallas versions V100R001C10

E5573Cs-609 versions earlier than TCPU-V200R001B328D01SP00C00

E5573s-320 versions TCPU-V200R001B180D11SP00C00

E5673s-609 versions earlier than TCPU-V200R001B328D01SP00C00

E5771s-856 versions earlier than TCPU-V200R001B329D07SP00C00

E5878s-32 versions TCPU-V200R001B280D01SP05C00

E6000 Chassis versions V100R001C00

Enterprise Service Solution EIDC versions V100R001C60

FusionCompute versions V100R003C10SPC600 V100R005C00 V100R005C10 V100R005C10U1_B1075917

FusionCube versions V100R002C60RC1

FusionManager versions V100R003C00 V100R003C10 V100R005C00 V100R005C00SPC100 V100R005C00SPC200 V100R005C00SPC300 V100R005C10 V100R005C10SPC300 V100R005C10SPC500 V100R005C10SPC700 V100R005C10SPC703 V100R005C10SPC720T V100R005C10U1_B1075133 V100R005C10U2

FusionStorage Block versions V100R003C00 V100R003C02 V100R003C30

FusionStorage Object versions V100R002C00 V100R002C01

HiDPTAndroid versions V200R001C00 V300R001C00

HiSTBAndroid versions V600R003C00SPC010

Huawei solutions for SAP HANA versions V100R001C00

IPC6122-D versions V100R001C10

IPC6611-Z30-I versions V100R001C00

KII-L21 versions C10B130CUSTC10D003 C185B130CUSTC185D002 C185B140CUSTC185D004 C636B310CUSTC636D001 OTA-C02B131CUSTC02D002 OTA-C185B140CUSTC185D004 OTA-C185B310CUSTC185D004 OTA-C636B140CUSTC636D004 OTA-C636B310CUSTC636D001 OTA-C636B320CUSTC636D001 Versions earlier than C02B140CUSTC02D001 Versions earlier than C10B150CUSTC10D003 Versions earlier than C185B321CUSTC185D001 Versions earlier than C464B140 Versions earlier than C629B140CUSTC629D001 Versions earlier than C636B160CUSTC636D001 Versions earlier than C636B160CUSTC636D001 Versions earlier than C636B160CUSTC636D001 Versions earlier than C636B330CUSTC636D002 Versions earlier than C900B130 Versions earlier than C96B140CUSTC96D004

L2800 versions V100R001C00SPC200

LogCenter versions V100R001C10

NEM-AL10 versions earlier than C00B355

NMO-L22 versions earlier than C569B150

OTA- versions KII-L21C636B150CUSTC636D005

OceanStor 18500 versions V100R001C10

OceanStor 18500 V3 versions V300R003C10

OceanStor 18800 V3 versions V300R003C00

OceanStor 5600 V3 versions V300R003C00 V300R003C10

OceanStor Backup Software versions V100R002C00 V100R002C00LHWS01_P385795 V100R002C00SPC200 V200R001C00 V200R001C00SPC200

OceanStor CSE versions V100R001C01SPC103 V100R001C01SPC106 V100R001C01SPC109 V100R001C01SPC112 V100R002C00LSFM01CP0001 V100R002C00LSFM01SPC101 V100R002C00LSFM01SPC102 V100R002C00LSFM01SPC106

OceanStor HDP3500E versions V100R002C00 V100R003C00

OceanStor HVS85T versions V100R001C00 V100R001C10 V100R001C30

OceanStor HVS88T versions V100R001C00

OceanStor N8500 versions V200R001C09 V200R001C91 V200R001C91SPC900

OceanStor Onebox versions V100R003C10

OceanStor ReplicationDirector versions V200R001C00

Onebox Solution versions V100R005C00 V1R5C00RC2

RH1288 V2 versions V100R002C00

RH1288 V3 versions V100R003C00

RH1288A V2 versions V100R002C00

RH2285 V2 versions V100R002C00

RH2285H V2 versions V100R002C00

RH2288 V2 versions V100R002C00

RH2288 V3 versions V100R003C00

RH2288A V2 versions V100R002C00

RH2288E V2 versions V100R002C00

RH2288H V2 versions V100R002C00

RH2288H V3 versions V100R003C00

RH2485 V2 versions V100R002C00

RH5885 V3 versions V100R003C01 V100R003C10

RH5885H V3 versions V100R003C00 V100R003C10

RH8100 V3 versions V100R003C00

V1300N versions V100R002C02

VCM versions V100R001C00 V100R001C10 V100R001C20

VIE-L29 versions earlier than C185B384 Versions earlier than C605B370

X6000 versions V100R002C00

X6800 versions V100R003C00

eCloud CC versions V100R001C01LSHU01

eLog versions V200R003C10 V200R003C20

eOMC910 versions V100R003C00

eSight versions V300R003C20 V300R005C00SPC200

eSight Network versions V300R006C00 V300R007C00

eSpace 8950 versions V200R003C00

eSpace IPC versions V100R001C21 V200R001C01 V200R001C02

eSpace VCN3000 versions V100R001C01 V100R002C00 V100R002C10 V100R002C20

inCloud Eye versions V200R001C21 V200R001C30

inCloud Payment versions V200R001C30

inCloud Shield versions V200R001C30");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20161207-01-dirtycow-en");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66); # nb: Unknown device (no VRP), no public vendor advisory or general inconsistent / broken data
