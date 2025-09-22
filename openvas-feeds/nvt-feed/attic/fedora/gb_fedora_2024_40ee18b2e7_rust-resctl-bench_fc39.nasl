# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887174");
  script_version("2025-04-24T05:40:01+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-04-24 05:40:01 +0000 (Thu, 24 Apr 2025)");
  script_tag(name:"creation_date", value:"2024-06-07 06:36:20 +0000 (Fri, 07 Jun 2024)");
  script_name("Fedora: Security Advisory for rust-resctl-bench (FEDORA-2024-40ee18b2e7)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-40ee18b2e7");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/DNTXAUIFF5MFYJ7TEYTZO3REUTDS7W3C");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust-resctl-bench'
  package(s) announced via the FEDORA-2024-40ee18b2e7 advisory.
Note: This VT has been deprecated as a duplicate.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"resctl-bench is a collection of whole-system benchmarks to evaluate resource
control and hardware behaviors using realistic simulated workloads.

Comprehensive resource control involves the whole system. Furthermore, testing
resource control end-to-end requires scenarios involving realistic workloads
and monitoring their interactions. The combination makes benchmarking resource
control challenging and error-prone. It&#39,s easy to slip up on a configuration
and testing with real workloads can be tedious and unreliable.

resctl-bench encapsulates the whole process so that resource control benchmarks
can be performed easily and reliably. It verifies and updates system
configurations, reproduces resource contention scenarios with a realistic
latency-sensitive workload simulator and other secondary workloads, analyzes
the resulting system and workload behaviors, and generates easily
understandable reports.");

  script_tag(name:"affected", value:"'rust-resctl-bench' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
