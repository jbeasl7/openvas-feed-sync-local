# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882703");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-04-21 06:41:57 +0200 (Fri, 21 Apr 2017)");
  script_cve_id("CVE-2017-5429", "CVE-2017-5432", "CVE-2017-5433", "CVE-2017-5434",
                "CVE-2017-5435", "CVE-2017-5436", "CVE-2017-5437", "CVE-2017-5438",
                "CVE-2017-5439", "CVE-2017-5440", "CVE-2017-5441", "CVE-2017-5442",
                "CVE-2017-5443", "CVE-2017-5444", "CVE-2017-5445", "CVE-2017-5446",
                "CVE-2017-5447", "CVE-2017-5448", "CVE-2017-5449", "CVE-2017-5459",
                "CVE-2017-5460", "CVE-2017-5464", "CVE-2017-5465", "CVE-2017-5469");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-07 17:53:00 +0000 (Tue, 07 Aug 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for firefox CESA-2017:1104 centos6");
  script_tag(name:"summary", value:"Check the version of firefox");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Mozilla Firefox is an open source web browser.

This update upgrades Firefox to version 52.1.0 ESR.

Security Fix(es):

  * Multiple flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user running
Firefox. (CVE-2017-5429, CVE-2017-5432, CVE-2017-5433, CVE-2017-5434,
CVE-2017-5435, CVE-2017-5436, CVE-2017-5437, CVE-2017-5438, CVE-2017-5439,
CVE-2017-5440, CVE-2017-5441, CVE-2017-5442, CVE-2017-5443, CVE-2017-5444,
CVE-2017-5445, CVE-2017-5446, CVE-2017-5447, CVE-2017-5448, CVE-2017-5449,
CVE-2017-5459, CVE-2017-5460, CVE-2017-5464, CVE-2017-5465, CVE-2017-5469)

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Mozilla developers and community, Nils, Holger
Fuhrmannek, Atte Kettunen, Huzaifa Sidhpurwala, Nicolas Gregoire, Chamal De
Silva, Chun Han Hsiao, Ivan Fratric of Google Project Zero, Anonymous
working with Trend Micro's Zero Day Initiative, and Petr Cerny as the
original reporters.");
  script_tag(name:"affected", value:"firefox on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2017:1104");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2017-April/022394.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~52.1.0~2.el6.centos", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
