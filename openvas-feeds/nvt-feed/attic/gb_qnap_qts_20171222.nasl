# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113076");
  script_version("2023-09-27T05:05:31+0000");
  script_tag(name:"last_modification", value:"2023-09-27 05:05:31 +0000 (Wed, 27 Sep 2023)");
  script_tag(name:"creation_date", value:"2018-01-09 11:55:11 +0100 (Tue, 09 Jan 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-04 18:43:00 +0000 (Thu, 04 Jan 2018)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-17027", "CVE-2017-17028", "CVE-2017-17029", "CVE-2017-17030",
                "CVE-2017-17031", "CVE-2017-17032", "CVE-2017-17033");

  script_name("QNAP QTS Multiple RCE Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");

  script_tag(name:"summary", value:"QNAP QTS is prone to multiple remote code execution
  (RCE) vulnerabilities.

  This VT was deprecated since it is a duplicate of QNAP QTS < 4.2.6 build 20171208, 4.3.3.x <
  4.3.3.0396 build 20171205, 4.3.4.x < 4.3.4.0411 build 20171208 Multiple Vulnerabilities
  (OID: 1.3.6.1.4.1.25623.1.0.107274)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  execute arbitrary code on the machine.");

  script_tag(name:"affected", value:"QNAP QTS versions 4.2.6 build 20171026, 4.3.3 build
  20171117, 4.3.4 build 20171116 and earlier.");

  script_tag(name:"solution", value:"Update to QNAP QTS version 4.2.6 build 20171208,
  4.3.3 build 20171205 or 4.3.4 build 20171208 respectively.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/nas-201712-15");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);