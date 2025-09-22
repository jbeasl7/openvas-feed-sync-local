# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-July/016750.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880608");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2010:0505");
  script_cve_id("CVE-2007-4829");
  script_name("CentOS Update for perl-Archive-Tar CESA-2010:0505 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-Archive-Tar'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"perl-Archive-Tar on CentOS 5");
  script_tag(name:"insight", value:"The Archive::Tar module provides a mechanism for Perl scripts to manipulate
  tar archive files.

  Multiple directory traversal flaws were discovered in the Archive::Tar
  module. A specially-crafted tar file could cause a Perl script, using the
  Archive::Tar module to extract the archive, to overwrite an arbitrary file
  writable by the user running the script. (CVE-2007-4829)

  This package upgrades the Archive::Tar module to version 1.39_01. Refer to
  the Archive::Tar module's changes file, linked to in the References, for a
  full list of changes.

  Users of perl-Archive-Tar are advised to upgrade to this updated package,
  which corrects these issues. All applications using the Archive::Tar module
  must be restarted for this update to take effect.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"perl-Archive-Tar", rpm:"perl-Archive-Tar~1.39.1~1.el5_5.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
