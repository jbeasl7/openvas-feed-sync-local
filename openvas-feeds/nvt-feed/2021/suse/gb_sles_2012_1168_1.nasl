# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2012.1168.1");
  script_cve_id("CVE-2012-4048", "CVE-2012-4049", "CVE-2012-4285", "CVE-2012-4288", "CVE-2012-4289", "CVE-2012-4290", "CVE-2012-4291", "CVE-2012-4292", "CVE-2012-4293", "CVE-2012-4296");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:26 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2012:1168-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4|SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2012:1168-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2012/suse-su-20121168-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the SUSE-SU-2012:1168-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"wireshark was updated to 1.4.15 to fix multiple security issues.

Issues fixed:

 * fix bnc#776038(CVE-2012-4285, CVE-2012-4288,
CVE-2012-4289, CVE-2012-4296, CVE-2012-4291, CVE-2012-4292,
CVE-2012-4293, CVE-2012-4290), bnc#772738 (CVE-2012-4048,
CVE-2012-4049)(fixed upstream)
 * Security fixes: o wnpa-sec-2012-13 The DCP ETSI dissector could trigger a zero division. Reported by Laurent Butti. (Bug 7566) o wnpa-sec-2012-15 The XTP dissector could go into an infinite loop. Reported by Ben Schmidt. (Bug 7571) o wnpa-sec-2012-17 The AFP dissector could go into a large loop. Reported by Stefan Cornelius.
(Bug 7603) o wnpa-sec-2012-18 The RTPS2 dissector could overflow a buffer. Reported by Laurent Butti. (Bug 7568) o wnpa-sec-2012-20 The CIP dissector could exhaust system memory. Reported y Ben Schmidt. (Bug 7570) o wnpa-sec-2012-21 The STUN dissector could crash. Reported by Laurent Butti. (Bug 7569) o wnpa-sec-2012-22 The EtherCAT Mailbox dissector could abort. Reported by Laurent Butti. (Bug 7562) o wnpa-sec-2012-23 The CTDB dissector could go into a large loop. Reported by Ben Schmidt. (Bug 7573)
 * Bug fixes: o Wireshark crashes on opening very short NFS pcap file. (Bug 7498)
 * Updated Protocol Support o AFP, Bluetooth L2CAP, CIP,
CTDB, DCP ETSI, EtherCAT Mailbox, FC Link Control LISP,
NFS, RTPS2, SCTP, STUN, XTP

Security Issue references:

 * CVE-2012-4048
>
 * CVE-2012-4049
>
 * CVE-2012-4285
>
 * CVE-2012-4288
>
 * CVE-2012-4289
>
 * CVE-2012-4296
>
 * CVE-2012-4291
>
 * CVE-2012-4292
>
 * CVE-2012-4293
>
 * CVE-2012-4290CVE-2012-4048 CVE-2012-4048>
 * CVE-2012-4049
>");

  script_tag(name:"affected", value:"'wireshark' package(s) on SUSE Linux Enterprise Desktop 10-SP4, SUSE Linux Enterprise Desktop 11-SP2, SUSE Linux Enterprise Server 10-SP4, SUSE Linux Enterprise Server 11-SP2, SUSE Linux Enterprise Software Development Kit 11-SP2.");

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

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.4.15~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-devel", rpm:"wireshark-devel~1.4.15~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.4.15~0.2.1", rls:"SLES11.0SP2"))) {
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
