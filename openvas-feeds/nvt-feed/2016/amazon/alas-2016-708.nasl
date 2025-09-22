# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120697");
  script_cve_id("CVE-2016-1548", "CVE-2016-1550", "CVE-2016-2516", "CVE-2016-2518");
  script_tag(name:"creation_date", value:"2016-10-26 12:38:11 +0000 (Wed, 26 Oct 2016)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-10 13:15:00 +0000 (Thu, 10 Jun 2021)");

  script_name("Amazon Linux: Security Advisory (ALAS-2016-708)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2016-708");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2016-708.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp' package(s) announced via the ALAS-2016-708 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that an ntpd client could be forced to change from basic client/server mode to the interleaved symmetric mode. A remote attacker could use a spoofed packet that, when processed by an ntpd client, would cause that client to reject all future legitimate server responses, effectively disabling time synchronization on that client. (CVE-2016-1548)

An out-of-bounds access flaw was found in the way ntpd processed certain packets. An authenticated attacker could use a crafted packet to create a peer association with hmode of 7 and larger, which could potentially (although highly unlikely) cause ntpd to crash. (CVE-2016-2518)

A flaw was found in the way libntp performed message authentication. An attacker able to observe the timing of the comparison function used in packet authentication could potentially use this flaw to recover the message digest. (CVE-2016-1550)

Assertion failure in ntpd on duplicate IPs on unconfig directives (CVE-2016-2516)");

  script_tag(name:"affected", value:"'ntp' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.6p5~40.30.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-debuginfo", rpm:"ntp-debuginfo~4.2.6p5~40.30.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.6p5~40.30.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-perl", rpm:"ntp-perl~4.2.6p5~40.30.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntpdate", rpm:"ntpdate~4.2.6p5~40.30.amzn1", rls:"AMAZON"))) {
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
