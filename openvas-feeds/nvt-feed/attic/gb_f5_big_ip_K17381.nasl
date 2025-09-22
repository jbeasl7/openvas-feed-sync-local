# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105399");
  script_version("2025-02-27T08:17:42+0000");
  script_tag(name:"last_modification", value:"2025-02-27 08:17:42 +0000 (Thu, 27 Feb 2025)");
  script_tag(name:"creation_date", value:"2015-10-14 12:11:59 +0200 (Wed, 14 Oct 2015)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2014-0428");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("F5 BIG-IP - OpenJDK vulnerability CVE-2014-0428");

  script_category(ACT_GATHER_INFO);

  script_family("F5 Local Security Checks");
  script_copyright("Copyright (C) 2015 Greenbone AG");

  script_tag(name:"summary", value:"The remote host is missing a security patch.

  This VT has been deprecated due to the following vendor statement:

  F5 previously reported this product as vulnerable. Further research has allowed us to re-evaluate
  this product as not vulnerable to this CVE.");

  script_tag(name:"insight", value:"Unspecified vulnerability in Oracle Java SE 5.0u55, 6u65, and
  7u45, Java SE Embedded 7u45 and OpenJDK 7 allows remote attackers to affect confidentiality,
  integrity, and availability via vectors related to CORBA.");

  script_tag(name:"impact", value:"The vulnerable OpenJDK CORBA component is included, but is not
  used in supported configurations. A local attacker with access to modify and execute code related
  to the vulnerable components may be able to breach confidentiality, integrity, and availability of
  the BIG-IP host.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"No solution is required.

  Note: This VT is deprecated and thus doesn't require a solution.");

  script_xref(name:"URL", value:"https://my.f5.com/manage/s/article/K17381");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
