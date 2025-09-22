# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881808");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-10-29 15:26:14 +0530 (Tue, 29 Oct 2013)");
  script_cve_id("CVE-2013-4242");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_name("CentOS Update for libgcrypt CESA-2013:1457 centos6");

  script_tag(name:"affected", value:"libgcrypt on CentOS 6");
  script_tag(name:"insight", value:"The libgcrypt library provides general-purpose implementations of various
cryptographic algorithms.

It was found that GnuPG was vulnerable to the Yarom/Falkner flush+reload
cache side-channel attack on the RSA secret exponent. An attacker able to
execute a process on the logical CPU that shared the L3 cache with the
GnuPG process (such as a different local user or a user of a KVM guest
running on the same host with the kernel same-page merging functionality
enabled) could possibly use this flaw to obtain portions of the RSA secret
key. (CVE-2013-4242)

All libgcrypt users are advised to upgrade to this updated package, which
contains a backported patch to correct this issue.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2013:1457");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-October/019988.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libgcrypt'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"libgcrypt", rpm:"libgcrypt~1.4.5~11.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgcrypt-devel", rpm:"libgcrypt-devel~1.4.5~11.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}