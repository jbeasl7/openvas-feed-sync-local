# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.790810110139979");
  script_cve_id("CVE-2024-41708");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-7908ee39a9)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-7908ee39a9");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-7908ee39a9");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2314766");
  script_xref(name:"URL", value:"https://docs.adacore.com/corp/security-advisories/SEC.AWS-0040-v2.pdf");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'aws' package(s) announced via the FEDORA-2024-7908ee39a9 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2024-41708: Ada Web Server did not use a cryptographically secure pseudorandom number generator.

AWS.Utils.Random and AWS.Utils.Random_String used Ada.Numerics.Discrete_Random, which is not designed to be cryptographically secure. Random_String also introduced a bias in the generated pseudorandom string values, where the values '1' and '2' had a much higher frequency than any other character.

The internal state of the Mersenne Twister PRNG could be revealed, and lead to a session hijacking attack.

This update fixes the problem by using /dev/urandom instead of Discrete_Random.

More details: [link moved to references]");

  script_tag(name:"affected", value:"'aws' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"aws", rpm:"aws~24.0.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aws-debuginfo", rpm:"aws-debuginfo~24.0.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aws-debugsource", rpm:"aws-debugsource~24.0.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aws-devel", rpm:"aws-devel~24.0.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aws-doc", rpm:"aws-doc~24.0.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aws-tools", rpm:"aws-tools~24.0.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aws-tools-debuginfo", rpm:"aws-tools-debuginfo~24.0.0~3.fc41", rls:"FC41"))) {
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
