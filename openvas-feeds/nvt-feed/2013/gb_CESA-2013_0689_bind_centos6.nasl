# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-March/019672.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881702");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-04-02 12:26:55 +0530 (Tue, 02 Apr 2013)");
  script_cve_id("CVE-2013-2266");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_xref(name:"CESA", value:"2013:0689");
  script_name("CentOS Update for bind CESA-2013:0689 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"bind on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The Berkeley Internet Name Domain (BIND) is an implementation of the
  Domain Name System (DNS) protocols. BIND includes a DNS server (named), a
  resolver library (routines for applications to use when interfacing with
  DNS), and tools for verifying that the DNS server is operating correctly.

  A denial of service flaw was found in the libdns library. A remote attacker
  could use this flaw to send a specially-crafted DNS query to named that,
  when processed, would cause named to use an excessive amount of memory, or
  possibly crash. (CVE-2013-2266)

  Note: This update disables the syntax checking of NAPTR (Naming Authority
  Pointer) resource records.

  This update also fixes the following bug:

  * Previously, rebuilding the bind-dyndb-ldap source RPM failed with a
  '/usr/include/dns/view.h:76:21: error: dns/rrl.h: No such file or
  directory' error. (BZ#928439)

  All bind users are advised to upgrade to these updated packages, which
  contain patches to correct these issues. After installing the update, the
  BIND daemon (named) will be restarted automatically.");
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

  if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.8.2~0.17.rc1.el6_4.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-chroot", rpm:"bind-chroot~9.8.2~0.17.rc1.el6_4.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.8.2~0.17.rc1.el6_4.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.8.2~0.17.rc1.el6_4.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-sdb", rpm:"bind-sdb~9.8.2~0.17.rc1.el6_4.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.8.2~0.17.rc1.el6_4.4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
