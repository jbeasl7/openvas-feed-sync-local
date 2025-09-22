# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120639");
  script_cve_id("CVE-2015-7974", "CVE-2015-7977", "CVE-2015-7978", "CVE-2015-7979", "CVE-2015-8138", "CVE-2015-8158", "CVE-2016-4953");
  script_tag(name:"creation_date", value:"2016-02-11 05:16:47 +0000 (Thu, 11 Feb 2016)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-16 13:15:00 +0000 (Fri, 16 Jul 2021)");

  script_name("Amazon Linux: Security Advisory (ALAS-2016-649)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2016-649");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2016-649.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp' package(s) announced via the ALAS-2016-649 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that ntpd as a client did not correctly check the originate timestamp in received packets. A remote attacker could use this flaw to send a crafted packet to an ntpd client that would effectively disable synchronization with the server, or push arbitrary offset/delay measurements to modify the time on the client. (CVE-2015-8138)

A NULL pointer dereference flaw was found in the way ntpd processed 'ntpdc reslist' commands that queried restriction lists with a large amount of entries. A remote attacker could use this flaw to crash the ntpd process. (CVE-2015-7977)

It was found that NTP does not verify peer associations of symmetric keys when authenticating packets, which might allow remote attackers to conduct impersonation attacks via an arbitrary trusted key. (CVE-2015-7974)

A stack-based buffer overflow was found in the way ntpd processed 'ntpdc reslist' commands that queried restriction lists with a large amount of entries. A remote attacker could use this flaw to crash the ntpd process. (CVE-2015-7978)

It was found that when NTP is configured in broadcast mode, an off-path attacker could broadcast packets with bad authentication (wrong key, mismatched key, incorrect MAC, etc) to all clients. The clients, upon receiving the malformed packets, would break the association with the broadcast server. This could cause the time on affected clients to become out of sync over a longer period of time. (CVE-2015-7979)

A flaw was found in the way the ntpq client certain processed incoming packets in a loop in the getresponse() function. A remote attacker could potentially use this flaw to crash an ntpq client instance. (CVE-2015-8158)

A flaw was found in ntpd that allows remote attackers to cause a denial of service (ephemeral-association demobilization) by sending a spoofed crypto-NAK packet with incorrect authentication data at a certain time. (CVE-2016-4953)

(Updated 2016-10-18: CVE-2016-4953 was fixed in this release but was not previously part of this errata.)");

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

  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.6p5~36.29.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-debuginfo", rpm:"ntp-debuginfo~4.2.6p5~36.29.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.6p5~36.29.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-perl", rpm:"ntp-perl~4.2.6p5~36.29.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntpdate", rpm:"ntpdate~4.2.6p5~36.29.amzn1", rls:"AMAZON"))) {
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
