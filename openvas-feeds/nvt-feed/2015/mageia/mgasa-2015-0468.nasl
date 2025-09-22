# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131148");
  script_cve_id("CVE-2015-8045", "CVE-2015-8047", "CVE-2015-8048", "CVE-2015-8049", "CVE-2015-8050", "CVE-2015-8051", "CVE-2015-8052", "CVE-2015-8053", "CVE-2015-8054", "CVE-2015-8055", "CVE-2015-8056", "CVE-2015-8057", "CVE-2015-8058", "CVE-2015-8059", "CVE-2015-8060", "CVE-2015-8061", "CVE-2015-8062", "CVE-2015-8063", "CVE-2015-8064", "CVE-2015-8065", "CVE-2015-8066", "CVE-2015-8067", "CVE-2015-8068", "CVE-2015-8069", "CVE-2015-8070", "CVE-2015-8071", "CVE-2015-8401", "CVE-2015-8402", "CVE-2015-8403", "CVE-2015-8404", "CVE-2015-8405", "CVE-2015-8406", "CVE-2015-8407", "CVE-2015-8408", "CVE-2015-8409", "CVE-2015-8410", "CVE-2015-8411", "CVE-2015-8412", "CVE-2015-8413", "CVE-2015-8414", "CVE-2015-8415", "CVE-2015-8416", "CVE-2015-8417", "CVE-2015-8419", "CVE-2015-8420", "CVE-2015-8421", "CVE-2015-8422", "CVE-2015-8423", "CVE-2015-8424", "CVE-2015-8425", "CVE-2015-8426", "CVE-2015-8427", "CVE-2015-8428", "CVE-2015-8429", "CVE-2015-8430", "CVE-2015-8431", "CVE-2015-8432", "CVE-2015-8433", "CVE-2015-8434", "CVE-2015-8435", "CVE-2015-8436", "CVE-2015-8437", "CVE-2015-8438", "CVE-2015-8439", "CVE-2015-8440", "CVE-2015-8441", "CVE-2015-8442", "CVE-2015-8443", "CVE-2015-8444", "CVE-2015-8445", "CVE-2015-8446", "CVE-2015-8447", "CVE-2015-8448", "CVE-2015-8449", "CVE-2015-8450", "CVE-2015-8451", "CVE-2015-8452", "CVE-2015-8453");
  script_tag(name:"creation_date", value:"2015-12-10 09:05:50 +0000 (Thu, 10 Dec 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Mageia: Security Advisory (MGASA-2015-0468)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0468");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0468.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17313");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-32.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'flash-player-plugin' package(s) announced via the MGASA-2015-0468 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Adobe Flash Player 11.2.202.554 contains fixes to critical security vulnerabilities
found in earlier versions that could potentially allow an attacker to take control
of the affected system.

This update resolves heap buffer overflow vulnerabilities that could lead to code
execution (CVE-2015-8438, CVE-2015-8446).

This update resolves memory corruption vulnerabilities that could lead to code
execution (CVE-2015-8444, CVE-2015-8443, CVE-2015-8417, CVE-2015-8416, CVE-2015-8451,
CVE-2015-8047, CVE-2015-8053, CVE-2015-8045, CVE-2015-8051, CVE-2015-8060,
CVE-2015-8419, CVE-2015-8408).

This update resolves security bypass vulnerabilities (CVE-2015-8453, CVE-2015-8440,
CVE-2015-8409).

This update resolves a stack overflow vulnerability that could lead to code
execution (CVE-2015-8407).

This update resolves a type confusion vulnerability that could lead to code
execution (CVE-2015-8439).

This update resolves an integer overflow vulnerability that could lead to code
execution (CVE-2015-8445).

This update resolves a buffer overflow vulnerability that could lead to code
execution (CVE-2015-8415)

This update resolves use-after-free vulnerabilities that could lead to code
execution (CVE-2015-8050, CVE-2015-8049, CVE-2015-8437, CVE-2015-8450, CVE-2015-8449,
CVE-2015-8448, CVE-2015-8436, CVE-2015-8452, CVE-2015-8048, CVE-2015-8413,
CVE-2015-8412, CVE-2015-8410, CVE-2015-8411, CVE-2015-8424, CVE-2015-8422,
CVE-2015-8420, CVE-2015-8421, CVE-2015-8423, CVE-2015-8425, CVE-2015-8433,
CVE-2015-8432, CVE-2015-8431, CVE-2015-8426, CVE-2015-8430, CVE-2015-8427,
CVE-2015-8428, CVE-2015-8429, CVE-2015-8434, CVE-2015-8435, CVE-2015-8414,
CVE-2015-8052, CVE-2015-8059, CVE-2015-8058, CVE-2015-8055, CVE-2015-8057,
CVE-2015-8056, CVE-2015-8061, CVE-2015-8067, CVE-2015-8066, CVE-2015-8062,
CVE-2015-8068, CVE-2015-8064, CVE-2015-8065, CVE-2015-8063, CVE-2015-8405,
CVE-2015-8404, CVE-2015-8402, CVE-2015-8403, CVE-2015-8071, CVE-2015-8401,
CVE-2015-8406, CVE-2015-8069, CVE-2015-8070, CVE-2015-8441, CVE-2015-8442,
CVE-2015-8447).");

  script_tag(name:"affected", value:"'flash-player-plugin' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin", rpm:"flash-player-plugin~11.2.202.554~1.mga5.nonfree", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin-kde", rpm:"flash-player-plugin-kde~11.2.202.554~1.mga5.nonfree", rls:"MAGEIA5"))) {
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
