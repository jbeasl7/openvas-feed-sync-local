# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108778");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-26 15:05:00 +0000 (Mon, 26 Feb 2018)");

  script_cve_id("CVE-2017-15329");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: SQL Injection Vulnerabilities in Huawei UMA Product (huawei-sa-20171116-01-uma)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei");

  script_tag(name:"summary", value:"There is a SQL injection vulnerability in the operation and maintenance module of Huawei UMA Product.

  This VT has been deprecated and is therefore no longer functional.");

  script_tag(name:"insight", value:"There is a SQL injection vulnerability in the operation and maintenance module of Huawei UMA Product. An attacker logs in to the system as a common user and sends crafted HTTP requests that contain malicious SQL statements to the affected system. Due to a lack of input validation on HTTP requests that contain user-supplied input, successful exploitation may allow the attacker to execute arbitrary SQL queries. (Vulnerability ID: HWPSIRT-2017-08159)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2017-15329. Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"By exploiting this vulnerability, an attacker can execute arbitrary SQL queries.");

  script_tag(name:"affected", value:"UMA versions V200R001C00");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171116-01-uma-en");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66); # nb: Unknown device (no VRP), no public vendor advisory or general inconsistent / broken data
