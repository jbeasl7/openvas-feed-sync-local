# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871840");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2017-07-14 15:55:16 +0530 (Fri, 14 Jul 2017)");
  script_cve_id("CVE-2017-3142", "CVE-2017-3143");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for bind RHSA-2017:1679-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The Berkeley Internet Name Domain (BIND) is
  an implementation of the Domain Name System (DNS) protocols. BIND includes a DNS
  server (named) a resolver library (routines for applications to use when
  interfacing with DNS) and tools for verifying that the DNS server is operating
  correctly. Security Fix(es): * A flaw was found in the way BIND handled TSIG
  authentication for dynamic updates. A remote attacker able to communicate with
  an authoritative BIND server could use this flaw to manipulate the contents of a
  zone, by forging a valid TSIG or SIG(0) signature for a dynamic update request.
  (CVE-2017-3143) * A flaw was found in the way BIND handled TSIG authentication
  of AXFR requests. A remote attacker, able to communicate with an authoritative
  BIND server, could use this flaw to view the entire contents of a zone by
  sending a specially constructed request packet. (CVE-2017-3142) Red Hat would
  like to thank Internet Systems Consortium for reporting these issues. Upstream
  acknowledges Clement Berthaux (Synacktiv) as the original reporter of these
  issues. Bug Fix(es): * ICANN is planning to perform a Root Zone DNSSEC Key
  Signing Key (KSK) rollover during October 2017. Maintaining an up-to-date KSK,
  by adding the new root zone KSK, is essential for ensuring that validating DNS
  resolvers continue to function following the rollover. (BZ#1458234)");
  script_tag(name:"affected", value:"bind on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2017:1679-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2017-July/msg00004.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.8.2~0.62.rc1.el6_9.4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-chroot", rpm:"bind-chroot~9.8.2~0.62.rc1.el6_9.4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.8.2~0.62.rc1.el6_9.4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.8.2~0.62.rc1.el6_9.4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.8.2~0.62.rc1.el6_9.4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
