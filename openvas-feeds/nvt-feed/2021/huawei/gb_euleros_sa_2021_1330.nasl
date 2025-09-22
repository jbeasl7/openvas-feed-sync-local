# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1330");
  script_cve_id("CVE-2020-14093", "CVE-2020-14154", "CVE-2020-14954", "CVE-2020-28896");
  script_tag(name:"creation_date", value:"2021-02-22 08:39:01 +0000 (Mon, 22 Feb 2021)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-26 19:58:57 +0000 (Fri, 26 Jun 2020)");

  script_name("Huawei EulerOS: Security Advisory for mutt (EulerOS-SA-2021-1330)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1330");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2021-1330");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'mutt' package(s) announced via the EulerOS-SA-2021-1330 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mutt before 1.14.3 proceeds with a connection even if, in response to a GnuTLS certificate prompt, the user rejects an expired intermediate certificate.(CVE-2020-14154)

Mutt before 1.14.3 allows an IMAP fcc/postpone man-in-the-middle attack via a PREAUTH response.(CVE-2020-14093)

Mutt before 1.14.4 and NeoMutt before 2020-06-19 have a STARTTLS buffering issue that affects IMAP, SMTP, and POP3. When a server sends a 'begin TLS' response, the client reads additional data (e.g., from a man-in-the-middle attacker) and evaluates it in a TLS context, aka 'response injection.'(CVE-2020-14954)

Mutt before 2.0.2 and NeoMutt before 2020-11-20 did not ensure that $ssl_force_tls was processed if an IMAP server's initial server response was invalid. The connection was not properly closed, and the code could continue attempting to authenticate. This could result in authentication credentials being exposed on an unencrypted connection, or to a machine-in-the-middle.(CVE-2020-28896)");

  script_tag(name:"affected", value:"'mutt' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"mutt", rpm:"mutt~1.5.21~29.h3", rls:"EULEROS-2.0SP2"))) {
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
