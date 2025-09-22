# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108783");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-22 14:38:00 +0000 (Thu, 22 Feb 2018)");

  script_cve_id("CVE-2017-15342");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Denial of Service Vulnerability on Several Products (huawei-sa-20171206-01-ssl)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei");

  script_tag(name:"summary", value:"There is a denial of service vulnerability on several products.

  This VT has been deprecated and is therefore no longer functional.");

  script_tag(name:"insight", value:"There is a denial of service vulnerability on several products. The software does not correctly calculate the rest size in a buffer when handling SSL connections. A remote unauthenticated attacker could send a lot of crafted SSL messages to the device, successful exploit could cause no space in the buffer and then denial of service. (Vulnerability ID: HWPSIRT-2016-12099)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-15342.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"Successful exploit could cause no space in the buffer and then denial of service.");

  script_tag(name:"affected", value:"TE60 versions V600R006C00

TP3106 versions V100R002C00

eSpace U1981 versions V200R003C30SPC100");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171206-01-ssl-en");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66); # nb: Unknown device (no VRP), no public vendor advisory or general inconsistent / broken data
