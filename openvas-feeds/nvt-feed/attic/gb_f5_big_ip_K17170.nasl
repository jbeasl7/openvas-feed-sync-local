# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105361");
  script_version("2025-02-27T08:17:42+0000");
  script_tag(name:"last_modification", value:"2025-02-27 08:17:42 +0000 (Thu, 27 Feb 2025)");
  script_tag(name:"creation_date", value:"2015-09-18 14:39:37 +0200 (Fri, 18 Sep 2015)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2015-4736");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("F5 BIG-IP - Java vulnerability CVE-2015-4736");

  script_category(ACT_GATHER_INFO);

  script_family("F5 Local Security Checks");
  script_copyright("Copyright (C) 2015 Greenbone AG");

  script_tag(name:"summary", value:"The remote host is missing a security patch.

  This VT has been deprecated due to the following vendor statement:

  F5 previously reported this product as vulnerable. Further research has allowed us to re-evaluate
  this product as not vulnerable to this CVE.");

  script_tag(name:"insight", value:"Unspecified vulnerability in Oracle Java SE 7u80 and 8u45 allows
  remote attackers to affect confidentiality, integrity, and availability via unknown vectors
  related to Deployment. (CVE-2015-4736)");

  script_tag(name:"impact", value:"Confidentiality, integrity, and availability may be affected when
  exploited by attackers. However, affected F5 products that contain the vulnerable software
  component do not use them in a way that exposes this vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"No solution is required.

  Note: This VT is deprecated and thus doesn't require a solution.");

  script_xref(name:"URL", value:"https://my.f5.com/manage/s/article/K17170");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
