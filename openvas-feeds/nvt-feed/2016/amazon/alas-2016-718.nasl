# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120707");
  script_cve_id("CVE-2016-4951", "CVE-2016-4997", "CVE-2016-4998", "CVE-2016-9806");
  script_tag(name:"creation_date", value:"2016-10-26 12:38:14 +0000 (Wed, 26 Oct 2016)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-17 21:17:00 +0000 (Tue, 17 Jan 2023)");

  script_name("Amazon Linux: Security Advisory (ALAS-2016-718)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2016-718");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2016-718.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ALAS-2016-718 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was discovered in processing setsockopt for 32 bit processes on 64 bit systems. This flaw will allow attackers to alter arbitrary kernel memory when unloading a kernel module. This action is usually restricted to root-priveledged users but can also be leveraged if the kernel is compiled with CONFIG_USER_NS and CONFIG_NET_NS. (CVE-2016-4997)

An out-of-bounds heap memory access leading to a Denial of Service, heap disclosure, or further impact was found in setsockopt(). The function call is normally restricted to root, however some processes with cap_sys_admin may also be able to trigger this flaw in privileged container environments. (CVE-2016-4998)

A vulnerability was found in the Linux kernel. The pointer to the netlink socket attribute is not checked, which could cause a null pointer dereference when parsing the nested attributes in function tipc_nl_publ_dump().
This allows local users to cause a DoS. (CVE-2016-4951)

A double free vulnerability was found in netlink_dump, which could cause a denial of service or possibly other unspecified impact. (CVE-2016-9806)

(Updated on 2016-07-14: CVE-2016-4998 and CVE-2016-4951 were fixed in this version, but was not previously listed in this errata.)

(Updated on 2017-01-19: CVE-2016-9806 was fixed in this release but was previously not part of this errata.)");

  script_tag(name:"affected", value:"'kernel' package(s) on Amazon Linux.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "AMAZON") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.4.14~24.50.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~4.4.14~24.50.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo-common-i686", rpm:"kernel-debuginfo-common-i686~4.4.14~24.50.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo-common-x86_64", rpm:"kernel-debuginfo-common-x86_64~4.4.14~24.50.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.14~24.50.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~4.4.14~24.50.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~4.4.14~24.50.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.4.14~24.50.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-debuginfo", rpm:"kernel-tools-debuginfo~4.4.14~24.50.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-devel", rpm:"kernel-tools-devel~4.4.14~24.50.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~4.4.14~24.50.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf-debuginfo", rpm:"perf-debuginfo~4.4.14~24.50.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
