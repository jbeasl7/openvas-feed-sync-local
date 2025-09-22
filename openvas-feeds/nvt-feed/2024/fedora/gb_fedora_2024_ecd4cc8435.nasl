# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887334");
  script_cve_id("CVE-2024-3024");
  script_tag(name:"creation_date", value:"2024-08-06 07:34:11 +0000 (Tue, 06 Aug 2024)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-16 19:00:49 +0000 (Wed, 16 Apr 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2024-ecd4cc8435)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-ecd4cc8435");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-ecd4cc8435");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2271992");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tcpreplay' package(s) announced via the FEDORA-2024-ecd4cc8435 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Announcing v4.5.1

This release contains contributions from a record number of new contributors. This is greatly appreciated since I am a team of one, and do Tcpreplay maintenance in my spare time.

There are many bug fixes and new features. Most notable features:

 - AF_XDP socket support - if you have a newer Linux kernel, you will be able to transmit at line rates without having to install 3rd party kernel modules (e.g. netmap, PF_RING)
 - -w tcpreplay option - this overrides the -i option, and allows you to write to a PCAP file rather than an interface
 - --include and --exclude tcpreplay options - allows replay of a list of specific packet numbers to replay. This may slow things down, so consider using in combination with -w.
 - --fixhdrlen tcpreplay option - added to control action on packet length changes
 - -W tcpreplay option - suppress warnings when replaying
 - SLL2( Linux 'cooked' capture encapsulation v2)
 - Haiku support

What's Changed

 - Add support for LINUX_SLL2 by @btriller in #728
 - Feature #727 - Linux SLL v2 by @fklassen in #820
 - Bug #779 - honour overflow for all PPS values by @fklassen in #821
 - AF_XDP socket extension using libxdp api by @plangarbalint in #797
 - Feature #822 - AF_XDP socket extension by @fklassen in #823
 - Nanosec accurate packet processing by @plangarbalint in #796
 - Handle IPv6 fragment extension header by @ChuckCottrill in #832
 - Bug #837 - handle IPv6 fragment extension header by @fklassen in #838
 - Feature #796 - nanosecond packet processing by @fklassen in #836
 - configure.ac: unify search dirs for pcap and add lib32 by @shr-project in #819
 - Feature #839 - add pull request template by @fklassen in #840
 - ipv6 - add check for extension header length by @GabrielGanne in #842
 - Bug #827 PR #842 IPv6 extension header - staging by @fklassen in #859
 - add check for empty cidr by @GabrielGanne in #843
 - Bug #824 and PR #843: check for empty CIDR by @fklassen in #860
 - Add option to turn on/off fix packet header length by @ChuckCottrill in #846
 - Bug #703 #844 PR #846: optionally fix packet header length --fixhdrlen by @fklassen in #861
 - Bug 863: fix nansecond timestamp regression by @fklassen in #865
 - autotools - AC_HELP_STRING is obsolete in 2.70 by @GabrielGanne in #856
 - some Haiku support by @infrastation in #847
 - configure.ac: do not run conftest in case of cross compilation by @ChenQi1989 in #849
 - dlt_jnpr_ether_cleanup: check config before cleanup by @Marsman1996 in #851
 - Fix recursive tcpedit cleanup by @GabrielGanne in #855
 - Bug #813: back out PR #855 by @fklassen in #866
 - Bug #867 - run regfree() on close by @fklassen in #868
 - Bug #869 tcpprep memory leak include exclude by @fklassen in #870
 - Bug #811 - add check for invalid jnpr header length by @fklassen in #872
 - Bug #792 avoid assertion and other fixes by @fklassen in #873
 - Bug #844 tap: ignore TUNSETIFF EBUSY errors by ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'tcpreplay' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"tcpreplay", rpm:"tcpreplay~4.5.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tcpreplay-debuginfo", rpm:"tcpreplay-debuginfo~4.5.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tcpreplay-debugsource", rpm:"tcpreplay-debugsource~4.5.1~1.fc40", rls:"FC40"))) {
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
