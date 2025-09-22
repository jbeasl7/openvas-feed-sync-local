# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882868");
  script_version("2023-11-03T05:05:46+0000");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2018-04-10 08:48:13 +0200 (Tue, 10 Apr 2018)");
  script_cve_id("CVE-2018-5125", "CVE-2018-5127", "CVE-2018-5129", "CVE-2018-5144",
                "CVE-2018-5145", "CVE-2018-5146");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-13 13:44:00 +0000 (Wed, 13 Mar 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for thunderbird CESA-2018:0647 centos6");
  script_tag(name:"summary", value:"Check the version of thunderbird");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Mozilla Thunderbird is a standalone mail
  and newsgroup client.

This update upgrades Thunderbird to version 52.7.0.

Security Fix(es):

  * Mozilla: Memory safety bugs fixed in Firefox 59 and Firefox ESR 52.7
(MFSA 2018-07) (CVE-2018-5125)

  * Mozilla: Memory safety bugs fixed in Firefox ESR 52.7 (MFSA 2018-07)
(CVE-2018-5145)

  * Mozilla: Vorbis audio processing out of bounds write (MFSA 2018-08)
(CVE-2018-5146)

  * Mozilla: Buffer overflow manipulating SVG animatedPathSegList (MFSA
2018-07) (CVE-2018-5127)

  * Mozilla: Out-of-bounds write with malformed IPC messages (MFSA 2018-07)
(CVE-2018-5129)

  * Mozilla: Integer overflow during Unicode conversion (MFSA 2018-07)
(CVE-2018-5144)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Bob Clary, Olli Pettay, Christian Holler, Nils
Ohlmeier, Randell Jesup, Tyson Smith, Ralph Giles, Philipp, Jet Villegas,
Richard Zhu via Trend Micro's Zero Day Initiative, Nils, James Grant, and
Root Object as the original reporters.");
  script_tag(name:"affected", value:"thunderbird on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2018:0647");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2018-April/022813.html");
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

  if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~52.7.0~1.el6.centos", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
