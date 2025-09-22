# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.0855.1");
  script_cve_id("CVE-2016-7055", "CVE-2017-3731", "CVE-2017-3732");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:00 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:49+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:49 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-17 16:08:07 +0000 (Wed, 17 May 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:0855-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:0855-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20170855-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs4' package(s) announced via the SUSE-SU-2017:0855-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs4 fixes the following issues:
- New upstream LTS release 4.7.3 The embedded openssl sources were updated
 to 1.0.2k (CVE-2017-3731, CVE-2017-3732, CVE-2016-7055, bsc#1022085,
 bsc#1022086, bsc#1009528)
- No changes in LTS version 4.7.2
- New upstream LTS release 4.7.1
 * build: shared library support is now working for AIX builds
 * repl: passing options to the repl will no longer overwrite defaults
 * timers: recanceling a cancelled timers will no longer throw
- New upstream LTS version 4.7.0
 * build: introduce the configure --shared option for embedders
 * debugger: make listen address configurable in debugger server
 * dgram: generalized send queue to handle close, fixing a potential
 throw when dgram socket is closed in the listening event handler
 * http: introduce the 451 status code 'Unavailable For Legal Reasons'
 * gtest: the test reporter now outputs tap comments as yamlish
 * tls: introduce secureContext for tls.connect (useful for caching
 client certificates, key, and CA certificates)
 * tls: fix memory leak when writing data to TLSWrap instance during
 handshake
 * src: node no longer aborts when c-ares initialization fails
 * ported and updated system CA store for the new node crypto code
- New upstream LTS version 4.6.2
 * build:
 + It is now possible to build the documentation from the release
 tarball.
 * buffer:
 + Buffer.alloc() will no longer incorrectly return a zero filled
 buffer when an encoding is passed.
 * deps:
 + Upgrade npm in LTS to 2.15.11.
 * repl:
 + Enable tab completion for global properties.
 * url:
 + url.format() will now encode all '#' in search.
- Add missing conflicts to base package. It's not possible to have
 concurrent nodejs installations.
- enable usage of system certificate store on SLE11SP4 by requiring
 openssl1 (bsc#1000036)");

  script_tag(name:"affected", value:"'nodejs4' package(s) on SUSE Enterprise Storage 4, SUSE Linux Enterprise Module for Web Scripting 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs4", rpm:"nodejs4~4.7.3~14.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs4-debuginfo", rpm:"nodejs4-debuginfo~4.7.3~14.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs4-debugsource", rpm:"nodejs4-debugsource~4.7.3~14.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs4-devel", rpm:"nodejs4-devel~4.7.3~14.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs4-docs", rpm:"nodejs4-docs~4.7.3~14.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm4", rpm:"npm4~4.7.3~14.1", rls:"SLES12.0"))) {
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
