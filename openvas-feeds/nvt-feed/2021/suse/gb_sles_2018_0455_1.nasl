# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0455.1");
  script_cve_id("CVE-2017-16227", "CVE-2017-5495", "CVE-2018-5378", "CVE-2018-5379", "CVE-2018-5380", "CVE-2018-5381");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-14 18:39:35 +0000 (Wed, 14 Mar 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0455-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0455-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180455-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021669");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065641");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1079798");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1079799");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1079800");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1079801");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-February/003733.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'quagga' package(s) announced via the SUSE-SU-2018:0455-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for quagga fixes the following security issues:

- The Quagga BGP daemon contained a bug in the AS_PATH size calculation that
 could have been exploited to facilitate a remote denial-of-service attack via
 specially crafted BGP UPDATE messages. [CVE-2017-16227, bsc#1065641]

- The Quagga BGP daemon did not check whether data sent to peers via NOTIFY had
 an invalid attribute length. It was possible to exploit this issue and cause
 the bgpd process to leak sensitive information over the network to a
 configured peer. [CVE-2018-5378, bsc#1079798]

- The Quagga BGP daemon used to double-free memory when processing certain
 forms of UPDATE messages. This issue could be exploited by sending an
 optional/transitive UPDATE attribute that all conforming eBGP speakers should
 pass along. Consequently, a single UPDATE message could have affected many
 bgpd processes across a wide area of a network. Through this vulnerability,
 attackers could potentially have taken over control of affected bgpd
 processes remotely. [CVE-2018-5379, bsc#1079799]

- It was possible to overrun internal BGP code-to-string conversion tables in
 the Quagga BGP daemon. Configured peers could have exploited this issue and
 cause bgpd to emit debug and warning messages into the logs that would
 contained arbitrary bytes. [CVE-2018-5380, bsc#1079800]

- The Quagga BGP daemon could have entered an infinite loop if sent an invalid
 OPEN message by a configured peer. If this issue was exploited, then bgpd
 would cease to respond to any other events. BGP sessions would have been
 dropped and not be reestablished. The CLI interface would have been
 unresponsive. The bgpd daemon would have stayed in this state until
 restarted. [CVE-2018-5381, bsc#1079801]

- The Quagga daemon's telnet 'vty' CLI contains an unbounded memory allocation
 bug that could be exploited for a denial-of-service attack on the daemon.
 This issue has been fixed. [CVE-2017-5495, bsc#1021669]

- The telnet 'vty' CLI of the Quagga daemon is no longer enabled by default,
 because the passwords in the default 'zebra.conf' config file are now
 disabled. The vty interface is available via 'vtysh' utility using pam
 authentication to permit management access for root without password.
 [bsc#1021669]");

  script_tag(name:"affected", value:"'quagga' package(s) on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"quagga", rpm:"quagga~0.99.22.1~16.4.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"quagga", rpm:"quagga~0.99.22.1~16.4.1", rls:"SLES12.0SP1"))) {
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
