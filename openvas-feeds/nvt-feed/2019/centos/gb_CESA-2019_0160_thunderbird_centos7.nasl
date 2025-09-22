# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882998");
  script_version("2023-07-10T08:07:43+0000");
  script_cve_id("CVE-2018-12405", "CVE-2018-17466", "CVE-2018-18492", "CVE-2018-18493", "CVE-2018-18494", "CVE-2018-18498");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-12 12:55:00 +0000 (Tue, 12 Mar 2019)");
  script_tag(name:"creation_date", value:"2019-02-02 04:03:44 +0100 (Sat, 02 Feb 2019)");
  script_name("CentOS Update for thunderbird CESA-2019:0160 centos7");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"CESA", value:"2019:0160");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-February/023154.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the CESA-2019:0160 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Thunderbird is a standalone mail and newsgroup client.

This update upgrades Thunderbird to version 60.4.0.

Security Fix(es):

  * Mozilla: Memory safety bugs fixed in Firefox 64 and Firefox ESR 60.4
(CVE-2018-12405)

  * chromium-browser, firefox: Memory corruption in Angle (CVE-2018-17466)

  * Mozilla: Use-after-free with select element (CVE-2018-18492)

  * Mozilla: Buffer overflow in accelerated 2D canvas with Skia
(CVE-2018-18493)

  * Mozilla: Same-origin policy violation using location attribute and
performance.getEntries to steal cross-origin URLs (CVE-2018-18494)

  * Mozilla: Integer overflow when calculating buffer sizes for images
(CVE-2018-18498)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Christian Holler, Diego Calleja, Andrew McCreight,
Jon Coppeard, Natalia Csoregi, Nicolas B. Pierron, Tyson Smith, Nils, Atte
Kettunen, James Lee of Kryptos Logic, and r as the original reporters.");

  script_tag(name:"affected", value:"thunderbird on CentOS 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~60.4.0~1.el7.centos", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
