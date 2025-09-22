# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.100510210098101100987102");
  script_tag(name:"creation_date", value:"2025-04-21 04:05:10 +0000 (Mon, 21 Apr 2025)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-d5fdbedb7f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-d5fdbedb7f");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-d5fdbedb7f");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2359198");
  script_xref(name:"URL", value:"https://www.arin.net/announcements/20250116-tal/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rpki-client' package(s) announced via the FEDORA-2025-d5fdbedb7f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"# rpki-client 9.5

- rpki-client now includes `arin.tal` which is no longer legally encumbered. See [link moved to references]
- rpki-client reports Certification Authorities that do not meaningfully participate in the RPKI as non-functional CAs. By definition, a CA is non-functional if there is no currently valid Manifest. The number of such CAs is printed at the end of each run and more detailed information is available in the JSON (`-j`) and ometrics (`-m`) output.
- OpenBSD reliability errata 014: Incorrect internal RRDP state handling in rpki-client can lead to a denial of service. Affected are rpki-client versions 7.5 - 9.4.
- Termination of `rsync` child processes with `SIGTERM` is no longer treated as an error if rpki-client has sent this signal. This only affects `openrsync`.
- Do not exit filemode with an error if a `.gbr` or a `.tak` object contains control characters in its UTF-8 strings. Instead, only warn and emit a sanitized version in JSON output.

Upcoming breaking change:

- Starting with release 9.6, rpki-client will emit all key identifiers (AKI and SKI) encoded in JSON as bare hex strings without colons.");

  script_tag(name:"affected", value:"'rpki-client' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"rpki-client", rpm:"rpki-client~9.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpki-client-debuginfo", rpm:"rpki-client-debuginfo~9.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpki-client-debugsource", rpm:"rpki-client-debugsource~9.5~1.fc40", rls:"FC40"))) {
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
