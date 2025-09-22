# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108782");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-27 15:13:00 +0000 (Tue, 27 Mar 2018)");

  script_cve_id("CVE-2017-17132", "CVE-2017-17133");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Two Vulnerabilities of License Module in Some Huawei Products (huawei-sa-20171206-01-license)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei");

  script_tag(name:"summary", value:"There is a uncontrolled format string vulnerability when the license module of some Huawei products output the log information.

  This VT has been deprecated and is therefore no longer functional.");

  script_tag(name:"insight", value:"There is a uncontrolled format string vulnerability when the license module of some Huawei products output the log information. An authenticated attacker could exploit this vulnerability to cause a denial of service. (Vulnerability ID: HWPSIRT-2017-06138)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-17132.There is a null pointer reference vulnerability in license module of some Huawei products due to insufficient verification. If the license module processes a special malicious license file, the processing will crashed. The attacker can exploit this vulnerability to cause a denial of service. (Vulnerability ID: HWPSIRT-2017-09100)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-17133.Huawei has released software updates to fix these vulnerabilities. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"The attacker can exploit these vulnerabilities to cause a denial of service.");

  script_tag(name:"affected", value:"VP9660 versions V500R002C10");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171206-01-license-en");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66); # nb: Unknown device (no VRP), no public vendor advisory or general inconsistent / broken data
