# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108774");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-11 19:51:00 +0000 (Mon, 11 Dec 2017)");

  script_cve_id("CVE-2017-2722");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Input Validation Vulnerability in Multiple Huawei Products (huawei-sa-20170419-01-pse)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei");

  script_tag(name:"summary", value:"There is an input validation vulnerability in Huawei Multiple products.

  This VT has been deprecated and is therefore no longer functional.");

  script_tag(name:"insight", value:"There is an input validation vulnerability in Huawei Multiple products. Due to the lack of input validation on the device, a remote attacker may exploit this vulnerability by crafting a malformed packet and sending it to the device. A successful exploit could allow the attacker to cause a denial of service or execute arbitrary code. (Vulnerability ID: HWPSIRT-2016-12105)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-2722.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to cause a denial of service or execute arbitrary code.");

  script_tag(name:"affected", value:"DBS3900 TDD LTE versions V100R003C00 V100R004C10

DP300 versions V500R002C00

TE60 versions V100R001C01SPC100 V100R001C10 V100R003C00 V500R002C00 V600R006C00

TP3106 versions V100R001C06B020 V100R002C00

eSpace 7950 versions V200R003C00 V200R003C30

eSpace IAD versions V300R001C07SPCa00 V300R002C01SPCb00

eSpace U1981 versions V100R001C20SPC500 V100R001C30 V200R003C00 V200R003C00SPC200 V200R003C20SPH502 V200R003C30 V200R003C30SPC100");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20170419-01-pse-en");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66); # nb: Unknown device (no VRP), no public vendor advisory or general inconsistent / broken data
