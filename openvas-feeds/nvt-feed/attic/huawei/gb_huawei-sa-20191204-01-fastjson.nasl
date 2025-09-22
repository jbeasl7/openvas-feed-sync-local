# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108798");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: RCE Vulnerability in Fastjson (huawei-sa-20191204-01-fastjson)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei");

  script_tag(name:"summary", value:"A remote code execution (RCE) vulnerability exists in the open-
  source JSON parsing library Fastjson.

  This VT has been deprecated and is therefore no longer functional.");

  script_tag(name:"insight", value:"A remote code execution vulnerability exists in the open-source JSON parsing library Fastjson. Remote attackers can send crafted JSON data packets to exploit this vulnerability. Successfully exploit could allow the attacker to execute arbitrary code on the target Fastjson server. (Vulnerability ID: HWPSIRT-2019-07083)Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"Successfully exploit could allow the attacker to execute arbitrary code on the target Fastjson server.");

  script_tag(name:"affected", value:"FusionCompute versions 6.3.0 6.3.1 6.3.RC1 6.5.0 6.5.1 6.5.RC1

RSE6500 versions V100R001C00 V500R002C00 V500R002C00SPC900

eSpace ECS versions V300R001C00

iManager NetEco versions V600R008C10 V600R008C20 V600R008C20CP1101 V600R008C20SPC100 V600R008C20SPC200 V600R008C20SPC210 V600R008C30 V600R008C30CP2001 V600R008C30CP2002 V600R008C30CP2003 V600R008C30CP2302 V600R008C30CP2303 V600R008C30CP2401 V600R008C30SPC100 V600R008C30SPC200 V600R008C30SPC230 V600R008C30SPC240 V600R009C00 V600R009C00SPC100 V600R009C00SPC110 V600R009C00SPC200 V600R009C10CP1002 V600R009C10CP1003 V600R009C10SPC100

iManager NetEco 6000 versions V600R007C91SPC100 V600R008C00SPC100 V600R008C10SPC300 V600R008C20");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20191204-01-fastjson-en");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66); # nb: Unknown device (no VRP), no public vendor advisory or general inconsistent / broken data
