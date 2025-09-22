# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.1823.1");
  script_cve_id("CVE-2018-8956", "CVE-2020-11868", "CVE-2020-13817", "CVE-2020-15025");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-09 17:30:18 +0000 (Tue, 09 Jun 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:1823-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2|SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:1823-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20201823-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169740");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171355");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172651");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173334");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/992038");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-July/007066.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp' package(s) announced via the SUSE-SU-2020:1823-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ntp fixes the following issues:

ntp was updated to 4.2.8p15

- CVE-2020-11868: Fixed an issue which a server mode packet with spoofed source address
 frequently send to the client ntpd could have caused denial of service (bsc#1169740).
- CVE-2018-8956: Fixed an issue which could have allowed remote attackers to prevent
 a broadcast client from synchronizing its clock with a broadcast NTP server via spoofed
 mode 3 and mode 5 packets (bsc#1171355).
- CVE-2020-13817: Fixed an issue which an off-path attacker with the ability to query time
 from victim's ntpd instance could have modified the victim's clock by a limited amount (bsc#1172651).
- CVE-2020-15025: Fixed an issue which remote attacker could have caused denial of service by consuming
 the memory when a CMAC key was used andassociated with a CMAC algorithm in the ntp.keys (bsc#1173334).
- Removed an OpenSSL version warning (bsc#992038 and bsc#1125401).");

  script_tag(name:"affected", value:"'ntp' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP Applications 15.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.8p15~4.10.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-debuginfo", rpm:"ntp-debuginfo~4.2.8p15~4.10.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-debugsource", rpm:"ntp-debugsource~4.2.8p15~4.10.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.8p15~4.10.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-debuginfo", rpm:"ntp-debuginfo~4.2.8p15~4.10.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-debugsource", rpm:"ntp-debugsource~4.2.8p15~4.10.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.8p15~4.10.1", rls:"SLES15.0"))) {
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
