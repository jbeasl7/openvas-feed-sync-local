# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-March/018531.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881171");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-30 16:32:28 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2012-1569");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name:"CESA", value:"2012:0427");
  script_name("CentOS Update for libtasn1 CESA-2012:0427 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libtasn1'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"libtasn1 on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"libtasn1 is a library developed for ASN.1 (Abstract Syntax Notation One)
  structures management that includes DER (Distinguished Encoding Rules)
  encoding and decoding.

  A flaw was found in the way libtasn1 decoded DER data. An attacker could
  create carefully-crafted DER encoded input (such as an X.509 certificate)
  that, when parsed by an application that uses libtasn1 (such as
  applications using GnuTLS), could cause the application to crash.
  (CVE-2012-1569)

  Red Hat would like to thank Matthew Hall of Mu Dynamics for reporting this
  issue.

  Users of libtasn1 are advised to upgrade to these updated packages, which
  contain a backported patch to correct this issue. For the update to take
  effect, all applications linked to the libtasn1 library must be restarted,
  or the system rebooted.");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"libtasn1", rpm:"libtasn1~2.3~3.el6_2.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtasn1-devel", rpm:"libtasn1-devel~2.3~3.el6_2.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtasn1-tools", rpm:"libtasn1-tools~2.3~3.el6_2.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
