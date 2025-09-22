# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0170");
  script_cve_id("CVE-2024-29038", "CVE-2024-29039");
  script_tag(name:"creation_date", value:"2024-05-09 04:11:51 +0000 (Thu, 09 May 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2024-0170)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0170");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0170.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33175");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278071");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278075");
  script_xref(name:"URL", value:"https://vuldb.com/?id.262756");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tpm2-tools' package(s) announced via the MGASA-2024-0170 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the tpm2-tools package. This issue occurs due to a
missing check whether the magic number in attest is equal to
TPM2_GENERATED_VALUE, which can allow an attacker to generate arbitrary
quote data that may not be detected by tpm2_checkquote (CVE-2024-29038).
The pcr selection which is passed with the --pcr parameter is not
compared with the attest. So it is possible to fake a valid attestation
(CVE-2024-29039).
A vulnerability classified as problematic was found in tpm2-tools. This
vulnerability affects an unknown code of the file
tools/misc/tpm2_checkquote.c of the component pcr Selection Value
Handler. The manipulation with an unknown input leads to a comparison
vulnerability. The product compares two entities in a security-relevant
context, but the comparison is incorrect, which may lead to resultant
weaknesses.");

  script_tag(name:"affected", value:"'tpm2-tools' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"tpm2-tools", rpm:"tpm2-tools~5.5.1~1.mga9", rls:"MAGEIA9"))) {
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
