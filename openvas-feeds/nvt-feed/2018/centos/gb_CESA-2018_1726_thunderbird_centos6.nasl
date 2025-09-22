# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882891");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-05-30 05:46:51 +0200 (Wed, 30 May 2018)");
  script_cve_id("CVE-2018-5150", "CVE-2018-5154", "CVE-2018-5155", "CVE-2018-5159",
                "CVE-2018-5161", "CVE-2018-5162", "CVE-2018-5168", "CVE-2018-5170",
                "CVE-2018-5178", "CVE-2018-5183", "CVE-2018-5184", "CVE-2018-5185");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-13 13:44:00 +0000 (Wed, 13 Mar 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for thunderbird CESA-2018:1726 centos6");
  script_tag(name:"summary", value:"Check the version of thunderbird");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Mozilla Thunderbird is a standalone mail and newsgroup client.

This update upgrades Thunderbird to version 52.8.0.

Security Fix(es):

  * Mozilla: Memory safety bugs fixed in Firefox 60 and Firefox ESR 52.8
(CVE-2018-5150)

  * Mozilla: Backport critical security fixes in Skia (CVE-2018-5183)

  * Mozilla: Use-after-free with SVG animations and clip paths
(CVE-2018-5154)

  * Mozilla: Use-after-free with SVG animations and text paths
(CVE-2018-5155)

  * Mozilla: Integer overflow and out-of-bounds write in Skia (CVE-2018-5159)

  * Mozilla: Full plaintext recovery in S/MIME via chosen-ciphertext attack
(CVE-2018-5184)

  * Mozilla: Hang via malformed headers (CVE-2018-5161)

  * Mozilla: Encrypted mail leaks plaintext through src attribute
(CVE-2018-5162)

  * Mozilla: Lightweight themes can be installed without user interaction
(CVE-2018-5168)

  * Mozilla: Filename spoofing for external attachments (CVE-2018-5170)

  * Mozilla: Buffer overflow during UTF-8 to Unicode string conversion
through legacy extension (CVE-2018-5178)

  * Mozilla: Leaking plaintext through HTML forms (CVE-2018-5185)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

Red Hat would like to thank the Mozilla project for reporting
CVE-2018-5150, CVE-2018-5154, CVE-2018-5155, CVE-2018-5159, CVE-2018-5168,
CVE-2018-5178, and CVE-2018-5183. Upstream acknowledges Christoph Diehl,
Randell Jesup, Tyson Smith, Alex Gaynor, Ronald Crane, Julian Hector,
Kannan Vijayan, Jason Kratzer, Mozilla Developers, Nils, Ivan Fratric,
Wladimir Palant, and Root Object as the original reporters.");
  script_tag(name:"affected", value:"thunderbird on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"CESA", value:"2018:1726");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2018-May/022846.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~52.8.0~2.el6.centos", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
