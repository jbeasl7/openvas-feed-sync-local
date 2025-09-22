# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882321");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"creation_date", value:"2015-11-05 06:17:07 +0100 (Thu, 05 Nov 2015)");
  script_cve_id("CVE-2015-7181", "CVE-2015-7182", "CVE-2015-7183");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for nspr CESA-2015:1980 centos5");
  script_tag(name:"summary", value:"Check the version of nspr");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Network Security Services (NSS) is a set of libraries designed to support
cross-platform development of security-enabled client and server
applications. Netscape Portable Runtime (NSPR) provides platform
independence for non-GUI operating system facilities.

A use-after-poison flaw and a heap-based buffer overflow flaw were found in
the way NSS parsed certain ASN.1 structures. An attacker could use these
flaws to cause NSS to crash or execute arbitrary code with the permissions
of the user running an application compiled against the NSS library.
(CVE-2015-7181, CVE-2015-7182)

A heap-based buffer overflow was found in NSPR. An attacker could use this
flaw to cause NSPR to crash or execute arbitrary code with the permissions
of the user running an application compiled against the NSPR library.
(CVE-2015-7183)

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Tyson Smith, David Keeler and Ryan Sleevi as the
original reporter.

All nss and nspr users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues.");
  script_tag(name:"affected", value:"nspr on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"CESA", value:"2015:1980");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-November/021472.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
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

  if ((res = isrpmvuln(pkg:"nspr", rpm:"nspr~4.10.8~2.el5_11", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nspr-devel", rpm:"nspr-devel~4.10.8~2.el5_11", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
