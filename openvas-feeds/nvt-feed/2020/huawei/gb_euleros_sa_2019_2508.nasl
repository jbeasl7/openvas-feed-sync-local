# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2508");
  script_cve_id("CVE-2018-14349", "CVE-2018-14350", "CVE-2018-14351", "CVE-2018-14352", "CVE-2018-14353", "CVE-2018-14355", "CVE-2018-14356", "CVE-2018-14358", "CVE-2018-14359");
  script_tag(name:"creation_date", value:"2020-01-23 13:02:02 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-12 14:24:16 +0000 (Wed, 12 Sep 2018)");

  script_name("Huawei EulerOS: Security Advisory for mutt (EulerOS-SA-2019-2508)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-2508");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-2508");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'mutt' package(s) announced via the EulerOS-SA-2019-2508 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in Mutt before 1.10.1 and NeoMutt before 2018-07-16. imap/command.c mishandles a NO response without a message.(CVE-2018-14349)

An issue was discovered in Mutt before 1.10.1 and NeoMutt before 2018-07-16. imap/message.c has a stack-based buffer overflow for a FETCH response with a long INTERNALDATE field.(CVE-2018-14350)

An issue was discovered in Mutt before 1.10.1 and NeoMutt before 2018-07-16. imap/command.c mishandles a long IMAP status mailbox literal count size.(CVE-2018-14351)

An issue was discovered in Mutt before 1.10.1 and NeoMutt before 2018-07-16. imap_quote_string in imap/util.c does not leave room for quote characters, leading to a stack-based buffer overflow.(CVE-2018-14352)

An issue was discovered in Mutt before 1.10.1 and NeoMutt before 2018-07-16. imap_quote_string in imap/util.c has an integer underflow.(CVE-2018-14353)

An issue was discovered in Mutt before 1.10.1 and NeoMutt before 2018-07-16. imap/util.c mishandles '..' directory traversal in a mailbox name.(CVE-2018-14355)

An issue was discovered in Mutt before 1.10.1 and NeoMutt before 2018-07-16. pop.c mishandles a zero-length UID.(CVE-2018-14356)

An issue was discovered in Mutt before 1.10.1 and NeoMutt before 2018-07-16. imap/message.c has a stack-based buffer overflow for a FETCH response with a long RFC822.SIZE field.(CVE-2018-14358)

An issue was discovered in Mutt before 1.10.1 and NeoMutt before 2018-07-16. They have a buffer overflow via base64 data.(CVE-2018-14359)");

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

  if(!isnull(res = isrpmvuln(pkg:"mutt", rpm:"mutt~1.5.21~29.h1", rls:"EULEROS-2.0SP2"))) {
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
