# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120093");
  script_cve_id("CVE-2015-3405", "CVE-2015-5146", "CVE-2015-5194", "CVE-2015-5195", "CVE-2015-5219", "CVE-2015-7703");
  script_tag(name:"creation_date", value:"2015-09-08 11:17:14 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-19 15:13:00 +0000 (Mon, 19 Apr 2021)");

  script_name("Amazon Linux: Security Advisory (ALAS-2015-593)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2015-593");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2015-593.html");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/SecurityNotice#June_2015_NTP_Security_Vulnerabi");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp' package(s) announced via the ALAS-2015-593 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"As discussed upstream, a flaw was found in the way ntpd processed certain remote configuration packets. Note that remote configuration is disabled by default in NTP. (CVE-2015-5146)

It was found that the :config command can be used to set the pidfile and driftfile paths without any restrictions. A remote attacker could use this flaw to overwrite a file on the file system with a file containing the pid of the ntpd process (immediately) or the current estimated drift of the system clock (in hourly intervals). (CVE-2015-7703)

It was found that ntpd could crash due to an uninitialized variable when processing malformed logconfig configuration commands. (CVE-2015-5194)

It was found that ntpd exits with a segmentation fault when a statistics type that was not enabled during compilation (e.g. timingstats) is referenced by the statistics or filegen configuration command. (CVE-2015-5195)

It was discovered that sntp would hang in an infinite loop when a crafted NTP packet was received, related to the conversion of the precision value in the packet to double. (CVE-2015-5219)

A flaw was found in the way the ntp-keygen utility generated MD5 symmetric keys on big-endian systems. An attacker could possibly use this flaw to guess generated MD5 keys, which could then be used to spoof an NTP client or server. (CVE-2015-3405)");

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

  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.6p5~33.26.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-debuginfo", rpm:"ntp-debuginfo~4.2.6p5~33.26.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.6p5~33.26.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-perl", rpm:"ntp-perl~4.2.6p5~33.26.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntpdate", rpm:"ntpdate~4.2.6p5~33.26.amzn1", rls:"AMAZON"))) {
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
