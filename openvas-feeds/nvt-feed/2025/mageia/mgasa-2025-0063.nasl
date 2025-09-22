# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0063");
  script_cve_id("CVE-2023-2794", "CVE-2023-4232", "CVE-2023-4233", "CVE-2023-4234", "CVE-2023-4235");
  script_tag(name:"creation_date", value:"2025-02-14 04:07:15 +0000 (Fri, 14 Feb 2025)");
  script_version("2025-02-14T08:35:38+0000");
  script_tag(name:"last_modification", value:"2025-02-14 08:35:38 +0000 (Fri, 14 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2025-0063)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0063");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0063.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33841");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7141-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7151-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ofono' package(s) announced via the MGASA-2025-0063 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Sms decoder stack-based buffer overflow remote code execution
vulnerability within the decode_deliver() function. (CVE-2023-2794)
Sms decoder stack-based buffer overflow remote code execution
vulnerability within the decode_status_report() function.
(CVE-2023-4232)
Sms decoder stack-based buffer overflow remote code execution
vulnerability within the sms_decode_address_field(). (CVE-2023-4233)
Sms decoder stack-based buffer overflow remote code execution
vulnerability within the decode_submit_report() function.
(CVE-2023-4234)
Sms decoder stack-based buffer overflow remote code execution
vulnerability within the decode_deliver_report() function.
(CVE-2023-4235)");

  script_tag(name:"affected", value:"'ofono' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"lib64ofono-devel", rpm:"lib64ofono-devel~2.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libofono-devel", rpm:"libofono-devel~2.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofono", rpm:"ofono~2.1~1.1.mga9", rls:"MAGEIA9"))) {
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
