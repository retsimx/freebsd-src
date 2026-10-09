#!/usr/bin/env atf-sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Lewis Lakerink

atf_test_case no_mutation
no_mutation_head()
{
	atf_set "descr" "K-4 paths never call K-3 marker mutation primitives"
}
no_mutation_body()
{
	atf_check -s exit:0 -o match:"PASS: K-4 reachable paths are classify-only" \
	    sh "$(atf_get_srcdir)/no-mutation-check.sh"
}

atf_test_case source_contracts
source_contracts_head()
{
	atf_set "descr" "K-4 provider, guard, extent, and header contracts"
}
source_contracts_body()
{
	atf_check -s exit:0 -o match:"PASS: K-4 source contracts" \
	    sh "$(atf_get_srcdir)/source-contract-check.sh"
}

atf_init_test_cases()
{
	atf_add_test_case no_mutation
	atf_add_test_case source_contracts
}
