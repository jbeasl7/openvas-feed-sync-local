# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.0975.1");
  script_cve_id("CVE-2026-27962", "CVE-2026-28490", "CVE-2026-28498");
  script_tag(name:"creation_date", value:"2026-03-26 04:48:36 +0000 (Thu, 26 Mar 2026)");
  script_version("2026-03-26T06:06:30+0000");
  script_tag(name:"last_modification", value:"2026-03-26 06:06:30 +0000 (Thu, 26 Mar 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-17 20:40:37 +0000 (Tue, 17 Mar 2026)");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:0975-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0975-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260975-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259736");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259737");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259738");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024822.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-Authlib' package(s) announced via the SUSE-SU-2026:0975-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-Authlib fixes the following issues:

- CVE-2026-27962: JWS `deserialize_compact()` allows for signature bypass by accepting user-controlled embedded JWK as
 verification key (bsc#1259738).
- CVE-2026-28490: cryptographic padding oracle in JWE RSA1_5 key management algorithm (bsc#1259736).
- CVE-2026-28498: fail-open in behavior OIDC hash validation allows for bypass mandatory integrity protections
 (bsc#1259737).");

  script_tag(name:"affected", value:"'python-Authlib' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"python311-Authlib", rpm:"python311-Authlib~1.3.1~150600.3.17.1", rls:"openSUSELeap15.6"))) {
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
