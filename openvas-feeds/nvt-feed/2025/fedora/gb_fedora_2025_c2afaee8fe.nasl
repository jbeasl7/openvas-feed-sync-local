# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.99297102971011018102101");
  script_tag(name:"creation_date", value:"2025-08-14 04:10:50 +0000 (Thu, 14 Aug 2025)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-c2afaee8fe)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-c2afaee8fe");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-c2afaee8fe");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2366662");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2381085");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'open62541' package(s) announced via the FEDORA-2025-c2afaee8fe advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Changes in v1.4.13:

* server: Cover edge-case in the EventFilter validation
* client: Cover edge-case in the UserTokenPolicy validation
* arch: Process delayed callbacks immediately via the nextCyclicTime
* plugins: Fixed memleak for scandir in OpenSSL SecurityPolicies
* tools: Fixed parsing of ByteString-NodeIds in the Nodeset compiler
* tools: Fix build-system edge-case in the Nodeset-Injector
* tools: Fixed edge-case for parsing of LocalizedText in the Nodeset compiler

Changes in v1.4.12:

* core: Added QNX support
* core: Fix use of null pointer in certificate verification
* arch: Fix busy loop in the EventLoop
* client: Check if the 'CreatedAt' timestamp of the SecurityToken
* client: Fix potential infinite loop in client connect
* server: Fix duplicate entries in discoveryUrls list
* server: Fix server lock state while copying out statistics
* deps: Update musl time methods to avoid name clashes
* plugin: Fix length calculation in mbedtls CreateCertificate
* ci: Run linux CI in a Ubuntu container");

  script_tag(name:"affected", value:"'open62541' package(s) on Fedora 42.");

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

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"open62541", rpm:"open62541~1.4.13~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open62541-debuginfo", rpm:"open62541-debuginfo~1.4.13~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open62541-debugsource", rpm:"open62541-debugsource~1.4.13~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open62541-devel", rpm:"open62541-devel~1.4.13~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open62541-doc", rpm:"open62541-doc~1.4.13~1.fc42", rls:"FC42"))) {
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
