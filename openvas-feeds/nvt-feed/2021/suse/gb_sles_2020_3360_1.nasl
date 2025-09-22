# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3360.1");
  script_cve_id("CVE-2017-16808", "CVE-2018-10103", "CVE-2018-10105", "CVE-2018-14461", "CVE-2018-14462", "CVE-2018-14463", "CVE-2018-14464", "CVE-2018-14465", "CVE-2018-14466", "CVE-2018-14467", "CVE-2018-14468", "CVE-2018-14469", "CVE-2018-14470", "CVE-2018-14879", "CVE-2018-14880", "CVE-2018-14881", "CVE-2018-14882", "CVE-2018-16227", "CVE-2018-16228", "CVE-2018-16229", "CVE-2018-16230", "CVE-2018-16300", "CVE-2018-16301", "CVE-2018-16451", "CVE-2018-16452", "CVE-2019-1010220", "CVE-2019-15166", "CVE-2019-15167", "CVE-2020-8037");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-07 17:37:15 +0000 (Mon, 07 Oct 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3360-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3360-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203360-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153098");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153332");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178466");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-November/007788.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tcpdump' package(s) announced via the SUSE-SU-2020:3360-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tcpdump fixes the following issues:

- CVE-2020-8037: Fixed an issue where PPP decapsulator did not allocate the right buffer size (bsc#1178466).

The previous update of tcpdump already fixed variuous Buffer overflow/overread vulnerabilities [bsc#1153098, bsc#1153332]

- CVE-2017-16808 (AoE)
- CVE-2018-14468 (FrameRelay)
- CVE-2018-14469 (IKEv1)
- CVE-2018-14470 (BABEL)
- CVE-2018-14466 (AFS/RX)
- CVE-2018-14461 (LDP)
- CVE-2018-14462 (ICMP)
- CVE-2018-14465 (RSVP)
- CVE-2018-14464 (LMP)
- CVE-2019-15166 (LMP)
- CVE-2018-14880 (OSPF6)
- CVE-2018-14882 (RPL)
- CVE-2018-16227 (802.11)
- CVE-2018-16229 (DCCP)
- CVE-2018-14467 (BGP)
- CVE-2018-14881 (BGP)
- CVE-2018-16230 (BGP)
- CVE-2018-16300 (BGP)
- CVE-2018-14463 (VRRP)
- CVE-2019-15167 (VRRP)
- CVE-2018-14879 (tcpdump -V)
- CVE-2018-16228 (HNCP) is a duplicate of the already fixed CVE-2019-1010220
- CVE-2018-16301 (fixed in libpcap)
- CVE-2018-16451 (SMB)
- CVE-2018-16452 (SMB)
- CVE-2018-10103 (SMB - partially fixed, but SMB printing disabled)
- CVE-2018-10105 (SMB - too unreliably reproduced, SMB printing disabled)");

  script_tag(name:"affected", value:"'tcpdump' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"tcpdump", rpm:"tcpdump~4.9.2~14.17.1", rls:"SLES12.0SP5"))) {
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
