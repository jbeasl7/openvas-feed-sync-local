# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143975");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2020-05-26 04:08:04 +0000 (Tue, 26 May 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-27 15:17:00 +0000 (Tue, 27 Feb 2018)");

  script_cve_id("CVE-2017-15333", "CVE-2017-15346");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Products Multiple DoS Vulnerabilities (huawei-sa-20171201-01-xml)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei");

  script_tag(name:"summary", value:"Multiple Huawei products are prone to multiple denial of service
  vulnerabilities in the XML parser.

  This VT has been deprecated as a duplicate of the VT 'Huawei Data Communication: Two DOS Vulnerabilities of XML Parser in Some Huawei Products (huawei-sa-20171201-01-xml)' (OID: 1.3.6.1.4.1.25623.1.0.108780).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An attacker may craft specific XML files to the affected products. Due to
  not check the specially XML file and to parse this file, successful exploit will result in DOS attacks.");

  script_tag(name:"impact", value:"An attacker can exploit these vulnerabilities to lead to DoS attacks.");

  script_tag(name:"affected", value:"Huawei S12700, S1700, S3700, S5700, S6700, S7700, S9700 and eCNS210_TD.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171201-01-xml-en");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
