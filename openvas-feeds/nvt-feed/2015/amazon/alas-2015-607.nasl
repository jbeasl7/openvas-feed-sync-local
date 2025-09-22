# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120597");
  script_cve_id("CVE-2015-5300", "CVE-2015-7691", "CVE-2015-7692", "CVE-2015-7701", "CVE-2015-7702", "CVE-2015-7704", "CVE-2015-7852", "CVE-2015-7871");
  script_tag(name:"creation_date", value:"2015-11-08 11:10:59 +0000 (Sun, 08 Nov 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-13 12:15:00 +0000 (Tue, 13 Apr 2021)");

  script_name("Amazon Linux: Security Advisory (ALAS-2015-607)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2015-607");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2015-607.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp' package(s) announced via the ALAS-2015-607 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that ntpd as a client did not correctly check timestamps in Kiss-of-Death packets. A remote attacker could use this flaw to send a crafted Kiss-of-Death packet to an ntpd client that would increase the client's polling interval value, and effectively disable synchronization with the server. (CVE-2015-7704)

It was found that ntpd did not correctly implement the threshold limitation for the '-g' option, which is used to set the time without any restrictions. A man-in-the-middle attacker able to intercept NTP traffic between a connecting client and an NTP server could use this flaw to force that client to make multiple steps larger than the panic threshold, effectively changing the time to an arbitrary value. (CVE-2015-5300)

It was found that the fix for CVE-2014-9750 was incomplete: three issues were found in the value length checks in ntp_crypto.c, where a packet with particular autokey operations that contained malicious data was not always being completely validated. Receipt of these packets can cause ntpd to crash. (CVE-2015-7691, CVE-2015-7692, CVE-2015-7702)

A potential off by one vulnerability exists in the cookedprint functionality of ntpq. A specially crafted buffer could cause a buffer overflow potentially resulting in null byte being written out of bounds. (CVE-2015-7852)

A memory leak flaw was found in ntpd's CRYPTO_ASSOC. If ntpd is configured to use autokey authentication, an attacker could send packets to ntpd that would, after several days of ongoing attack, cause it to run out of memory. (CVE-2015-7701)");

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

  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.6p5~34.27.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-debuginfo", rpm:"ntp-debuginfo~4.2.6p5~34.27.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.6p5~34.27.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-perl", rpm:"ntp-perl~4.2.6p5~34.27.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntpdate", rpm:"ntpdate~4.2.6p5~34.27.amzn1", rls:"AMAZON"))) {
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
