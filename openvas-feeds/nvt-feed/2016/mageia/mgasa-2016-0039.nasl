# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131203");
  script_cve_id("CVE-2015-7974", "CVE-2015-7977", "CVE-2015-7978", "CVE-2015-7979", "CVE-2015-8138", "CVE-2015-8158");
  script_tag(name:"creation_date", value:"2016-02-02 05:44:19 +0000 (Tue, 02 Feb 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-07 15:11:22 +0000 (Tue, 07 Feb 2017)");

  script_name("Mageia: Security Advisory (MGASA-2016-0039)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0039");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0039.html");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/SecurityNotice#January_2016_NTP_4_2_8p6_Securit");
  script_xref(name:"URL", value:"http://www.talosintel.com/reports/TALOS-2016-0071/");
  script_xref(name:"URL", value:"http://www.talosintel.com/reports/TALOS-2016-0074/");
  script_xref(name:"URL", value:"http://www.talosintel.com/reports/TALOS-2016-0075/");
  script_xref(name:"URL", value:"http://www.talosintel.com/reports/TALOS-2016-0076/");
  script_xref(name:"URL", value:"http://www.talosintel.com/reports/TALOS-2016-0077/");
  script_xref(name:"URL", value:"http://www.talosintel.com/reports/TALOS-2016-0080/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17606");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1297471");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1299442");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1300269");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1300270");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1300271");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1300273");
  script_xref(name:"URL", value:"https://github.com/ntp-project/ntp/commit/71a962710bfe066f76da9679cf4cfdeffe34e95e");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp' package(s) announced via the MGASA-2016-0039 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In ntpd before 4.2.8p6, when used with symmetric key encryption, the
client would accept packets encrypted with keys for any configured server,
allowing a server to impersonate other servers to clients, thus performing
a man-in-the-middle attack. A server can be attacked by a client in a
similar manner (CVE-2015-7974).

A NULL pointer dereference flaw was found in the way ntpd processed 'ntpdc
reslist' commands that queried restriction lists with a large amount of
entries. A remote attacker could use this flaw to crash the ntpd process
(CVE-2015-7977).

A stack-based buffer overflow was found in the way ntpd processed 'ntpdc
reslist' commands that queried restriction lists with a large amount of
entries. A remote attacker could use this flaw to crash the ntpd process
(CVE-2015-7978).

It was found that when NTP is configured in broadcast mode, an off-path
attacker could broadcast packets with bad authentication (wrong key,
mismatched key, incorrect MAC, etc) to all clients. The clients, upon
receiving the malformed packets, would break the association with the
broadcast server. This could cause the time on affected clients to become
out of sync over a longer period of time (CVE-2015-7979).

A faulty protection against spoofing and replay attacks allows an attacker
to disrupt synchronization with kiss-of-death packets, take full control
of the clock, or cause ntpd to crash (CVE-2015-8138).

A flaw was found in the way the ntpq client certain processed incoming
packets in a loop in the getresponse() function. A remote attacker could
potentially use this flaw to crash an ntpq client instance
(CVE-2015-8158).

The ntp package has been patched to fix these issues and a few other bugs.

Note that there are still some unfixed issues. Two of those issues,
CVE-2015-8139 and CVE-2015-8140, are vulnerabilities to spoofing and
replay attacks that can be mitigated by either adding the noquery option
to all restrict entries in ntp.conf, configuring ntpd to get time from
multiple sources, or using a restriction list to limit who is allowed to
issue ntpq and ntpdc queries.

Additionally, the other unfixed issues can also be mitigated.
CVE-2015-7973, a replay attack issue, can be mitigated by not using
broadcast mode, and CVE-2015-7976, a bug that can cause globbing issues
on the server, can be mitigated by restricting use of the 'saveconfig'
command with the 'restrict nomodify' directive.");

  script_tag(name:"affected", value:"'ntp' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.6p5~24.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-client", rpm:"ntp-client~4.2.6p5~24.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.6p5~24.4.mga5", rls:"MAGEIA5"))) {
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
