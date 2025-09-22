# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871498");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-11-20 06:24:26 +0100 (Fri, 20 Nov 2015)");
  script_cve_id("CVE-2012-2150");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for xfsprogs RHSA-2015:2151-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'xfsprogs'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The xfsprogs packages contain a set of
commands to use the XFS file system, including the mkfs.xfs command to construct
an XFS system.

It was discovered that the xfs_metadump tool of the xfsprogs suite did not
fully adhere to the standards of obfuscation described in its man page. In
case a user with the necessary privileges used xfs_metadump and relied on
the advertised obfuscation, the generated data could contain unexpected
traces of potentially sensitive information. (CVE-2012-2150)

The xfsprogs packages have been upgraded to upstream version 3.2.2, which
provides a number of bug fixes and enhancements over the previous version.
This release also includes updates present in upstream version 3.2.3,
although it omits the mkfs.xfs default disk format change (for metadata
checksumming) which is present upstream. (BZ#1223991)

Users of xfsprogs are advised to upgrade to these updated packages, which
fix these bugs and add these enhancements.");
  script_tag(name:"affected", value:"xfsprogs on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"RHSA", value:"2015:2151-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-November/msg00024.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"xfsprogs", rpm:"xfsprogs~3.2.2~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xfsprogs-debuginfo", rpm:"xfsprogs-debuginfo~3.2.2~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
