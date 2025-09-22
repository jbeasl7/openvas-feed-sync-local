# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108779");
  script_version("2024-07-03T06:48:05+0000");
  script_tag(name:"last_modification", value:"2024-07-03 06:48:05 +0000 (Wed, 03 Jul 2024)");
  script_tag(name:"creation_date", value:"2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2008-4250");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: RCE Vulnerability in Microsoft Windows Server Service (huawei-sa-20171129-01-windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei");

  script_tag(name:"summary", value:"Microsoft released a security bulletin MS08-067 to disclose a vulnerability in the Server service.

  This VT has been deprecated and is therefore no longer functional.");

  script_tag(name:"insight", value:"Microsoft released a security bulletin MS08-067 to disclose a vulnerability in the Server service. An unauthenticated, remote attacker may send a specially crafted RPC request to the affected products. Successful exploit may result in arbitrary code execution. (Vulnerability ID: HWPSIRT-2017-05167)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2008-4250.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"Successful exploit may result in arbitrary code execution.");

  script_tag(name:"affected", value:"AnyOffice versions V200R002C10 V200R002C20 V200R005C02

SMC2.0 versions V100R003C10 V500R002C00");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171129-01-windows-en");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66); # nb: Unknown device (no VRP), no public vendor advisory or general inconsistent / broken data
