# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856087");
  script_cve_id("CVE-2018-25099");
  script_tag(name:"creation_date", value:"2024-04-22 01:00:22 +0000 (Mon, 22 Apr 2024)");
  script_version("2025-02-26T05:38:40+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:40 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0112-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0112-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/UPEJCYLFV3FPQUS5GF63SP3V7CRAO2RX/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221528");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-CryptX' package(s) announced via the openSUSE-SU-2024:0112-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for perl-CryptX fixes the following issues:

Updated to version 0.080:

 0.080 2023-10-04
 - fix #95 AES-NI troubles on MS Windows (gcc compiler)
 - fix #96 Tests failure with Math::BigInt >= 1.999840
 - Enabled AES-NI for platforms with gcc/clang/llvm
 0.079 2023-10-01
 - fix #92 update libtomcrypt
 - bundled libtomcrypt update branch:develop (commit:1e629e6f 2023-06-22)
 0.078 2023-04-28
 - fix #89 Crypt::Mac::HMAC b64mac and b64umac object methods do not work");

  script_tag(name:"affected", value:"'perl-CryptX' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"perl-CryptX", rpm:"perl-CryptX~0.80.0~bp155.2.3.1", rls:"openSUSELeap15.5"))) {
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
