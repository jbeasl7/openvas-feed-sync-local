# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140035");
  script_version("2023-08-09T05:05:14+0000");
  script_tag(name:"last_modification", value:"2023-08-09 05:05:14 +0000 (Wed, 09 Aug 2023)");
  script_tag(name:"creation_date", value:"2016-10-28 12:33:04 +0200 (Fri, 28 Oct 2016)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)");

  script_cve_id("CVE-2016-5300", "CVE-2012-0876");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("F5 BIG-IP - Expat XML library vulnerability CVE-2016-5300");

  script_category(ACT_GATHER_INFO);
  script_family("F5 Local Security Checks");
  script_copyright("Copyright (C) 2016 Greenbone AG");

  script_tag(name:"summary", value:"F5 BIG-IP is prone to a vulnerability in the Expat XML library.

  This VT has been deprecated as a duplicate of the VT 'F5 BIG-IP - Expat XML library vulnerability
  CVE-2016-5300' (OID: 1.3.6.1.4.1.25623.1.0.140638).");

  script_tag(name:"insight", value:"The XML parser in Expat does not use sufficient entropy for hash
  initialization, which allows context-dependent attackers to cause a denial of service (CPU
  consumption) via crafted identifiers in an XML document.");

  script_tag(name:"impact", value:"An attacker may be able to cause a denial-of-service (DoS) attack
  via crafted identifiers in an XML document.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://my.f5.com/manage/s/article/K70938105");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);